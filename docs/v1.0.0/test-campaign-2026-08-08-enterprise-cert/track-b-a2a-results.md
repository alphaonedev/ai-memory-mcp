---
layout: doc
---
# Track B — A2A Multi-Agent Results, v1.0.0 Enterprise Certification

Per the campaign [`PLAN.md`](./PLAN.md) §2 Track B. Two IronClaw 1.1.0 "Reborn"
agents driven by **Grok 4.5** exchanged a memory through the ai-memory v1.0.0
substrate on **PostgreSQL 16 + Apache AGE 1.6.0 + pgvector**, over **HTTPS +
mTLS** with **agent attestation strict**. Run date **2026-08-09**.

**This is a RE-RUN.** The 2026-08-08 execution's evidence was ruled
unverifiable and is superseded in full — see
[§1 Why this re-run exists](#1-why-this-re-run-exists).

> **Stack-evidence note ([#2913](https://github.com/alphaonedev/ai-memory-mcp/issues/2913)).**
> The backend banner below is the **as-run record**: PostgreSQL 16.10 +
> Apache AGE 1.6.0 + **pgvector 0.8.6** (local single-node). It is not a
> PG18 run. The later enterprise-federation certification pins the
> disjoint **PG18.4 + AGE 1.7.0 + pgvector 0.8.5** single-node CI stack
> (run [`31601974424`](https://github.com/alphaonedev/ai-memory-mcp/actions/runs/31601974424)
> at `b80e7fff`). Track A/B recorded pgvector **0.8.6**; the DO 2-node
> mesh recorded **0.8.4** — both kept as written. See
> [`PLAN.md`](./PLAN.md) §"Stack-evidence reconciliation".

Every command, its verbatim stdout/stderr and its exit code are appended to
`.local-runs/cert-campaign/trackb/rerun-2026-08-09/evidence.log` (1,072 lines, 17 recorded steps — including the one IronClaw workspace-root
failure that preceded the successful alice run, retained rather than pruned).
The `trackb_a2a` database is **left in place** so every claim below can be
re-derived from the durable rows rather than from this document.

---

## Config banner (certified)

| Fact | Value |
|------|-------|
| Git commit | `5ceab18bf37ecc1fd00a3576b10fbb4d6c99fde7` (release/v1.0.0 tip) |
| Binary | `ai-memory 1.0.0`, `target/release/ai-memory`, **rebuilt at this commit** |
| Binary sha256 | `38b2d944ce5449ddeda710e969db3afaa61615f7667757f9df5c4fa970accf2a` |
| Signer | `target/release/examples/attest_sign`, sha256 `ed8f0f39db2f851b316fc7d6f352ac3876e10c6170a06370ce62086fb7a8793f` |
| Build | `cargo build --release --features sal,sal-postgres` |
| Toolchain | rustc 1.96.0 (`rust-toolchain.toml` pin) |
| Backend | **PostgreSQL 16.10 + Apache AGE 1.6.0 + pgvector 0.8.6**, fresh DB `trackb_a2a`, schema **v88**, 39 tables, AGE graph `memory_graph` created |
| Store URL delivery | `AI_MEMORY_STORE_URL_FILE` (0600) — keeps the password out of argv (#1927) |
| Encryption | **TLS ON** (rustls) + **mTLS ON** (SHA-256 client-cert fingerprint allowlist) |
| Attestation | **ON everywhere** — `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1` (strict on *every* write surface, not merely the surface-scoped HTTP-direct default of env #48/#1985) |
| Admin gate | no `api_key`; `AI_MEMORY_ADMIN_HEADER_TRUST=1` + `[admin] agent_ids=["ai:operator"]` (the #1570/H6 opt-in) |
| Recall tier | `tier=keyword` (FTS) — deterministic; embedder deliberately not loaded |
| A2A driver | **IronClaw 1.1.0** ×2 separate `IRONCLAW_REBORN_HOME`s (`ai:alice`, `ai:bob`), provider **openrouter**, model **`x-ai/grok-4.5`** |
| Agents | `ai:alice`, `ai:bob` registered + Ed25519 pubkeys bound over the admin HTTPS route |

**Deviation from PLAN.md §1, disclosed:** the plan pins the cert tip at
`715cb38f`. This re-run is at `5ceab18b`, four `src/`-touching commits later
(`0e767970`, `d44eb01a`, `7efd6e18`, plus `25329b2b`), because C5 step-7
recompile-retest discipline requires probing a binary built from the code under
test. Two of those commits (`0e767970`, `d44eb01a`) change
`src/store/postgres.rs` and the recall/KG paths this track exercises, so
running the older binary would have produced stale-binary evidence. `#1882`
(the dim fix PLAN.md requires) is an ancestor of this tip.

---

## Assertion summary

PLAN.md Track B pass criterion, split into its three clauses:

> *Two enrolled daemons exchange signed A2A signals/actions across the
> federation transport; cross-agent memory visible per governance; no unsigned
> authority-write accepted.*

| # | Assertion | Verdict | Where |
|---|-----------|---------|-------|
| B1 | Both agents enrolled with bound Ed25519 attestation keys | **PASS** | [§3](#3-enrollment) |
| B2 | mTLS gate refuses non-allowlisted / cert-less peers | **PASS** | [§3](#3-enrollment) |
| B3 | Agent-authored signed write lands `attest_level=agent_attested` | **PASS** | [§5](#5-alice--the-agentic-write) |
| B4 | **Cross-agent memory visible per governance** — bob reads alice's row with real content | **PASS** | [§6](#6-bob--the-agentic-read-the-a2a-assertion) |
| B5 | **No unsigned authority-write accepted** (5 negatives, incl. cross-key, replay, tamper) | **PASS** | [§7](#7-negative-assertions) |
| B6 | Refused writes leave **zero** durable rows | **PASS** | [§7](#7-negative-assertions) |
| B7 | AGE graph projection real (Cypher traversal + HTTP `kg_query`) | **PASS** | [§9](#9-age-graph-projection) |
| B8 | *"…across the **federation transport**"* — two **daemons**, multi-node | **NOT PROVEN — deferred to DO** | [§10](#10-honesty-ledger--proven-vs-deferred) |

**Track B verdict: PASS on the agent-to-agent and attestation clauses;
the multi-node federation-transport clause is NOT proven locally and is
deferred to the DigitalOcean round.** This is a scope limitation of a
single-daemon local harness, not an observed failure. No data-integrity
violation and no fail-closed violation was observed. **No new defects filed.**

---

## 1. Why this re-run exists

The 2026-08-08 Track B execution could not be verified: its `trackb_a2a`
database was recycled, and the sole surviving artifact was IronClaw bob's
persisted thread showing a recall that rendered as a row of nulls:

```
RECALL http=200 agent=ai:bob query="rendezvous cipher"
{"id":null,"title":null,"content":null,"agent":null,"attest":null}
```

Rather than assume, this re-run reconstructed what that artifact actually was
from IronClaw's own durable store plus the daemon's forensic audit chain
(evidence.log step 4b). Three independently checkable facts:

1. **The recall preceded the data.** Bob's recall is stamped
   `2026-08-08T15:18:58Z`. The daemon's forensic chain stamps alice's two
   `trackb-a2a` writes at `2026-08-09T00:43:09Z` and `00:43:23Z` — **~9.5 hours
   later**. At recall time the namespace was empty, so `count:0, memories:[]`
   was the *correct* substrate answer.
2. **A superseded shim produced it.** The artifact's summary line carries no
   `count=` field, but the `a2a-mem.sh` revision that shipped prints
   `… query="$query" count=$cnt`. The shim was edited at 2026-08-08 20:36 local
   (`00:36Z` on the 9th) — *after* the 15:18Z run. The transcript does not even
   exercise the shim the campaign later used.
3. **The null row is reproducible from an empty result.** `jq '.memories[] |
   {id,title,…}'` over an empty array emits **nothing**; `jq '.memories[0] |
   {id,title,…}'` over an empty array emits, byte-for-byte:
   `{"id":null,"title":null,"content":null,"agent":null,"attest":null}` —
   exactly the artifact (verified in evidence.log step 4c).

**Conclusion: the all-null row was a reporting artifact of a superseded shim
revision rendering a correctly-empty result set.** It is evidence of neither a
substrate defect nor a jq-path bug in the shipped shim — §4 below shows the
shipped extraction returning full correct values against a real row.

It nevertheless *was* a legitimate reason to void the prior evidence: the
summary line under-reported (no row count), the raw response was never echoed,
and an empty result rendered as a populated-looking row. All three are fixed in
the `rerun-2026-08-09/a2a-mem.sh` revision, which now (a) always echoes the raw
response bytes before any parsing, (b) type-asserts each row instead of
silently rendering `null` as an object, and (c) surfaces non-2xx/non-JSON
instead of swallowing them.

### Environment fix folded in

The prior run's daemon logged a **fail-closed deferred-audit failure**:

```
ERROR deferred-audit journal open failed …: deferred-audit spool ancestor
permits untrusted rename: …/cert-campaign/trackb/.
```

Cause: two ancestor directories were group-writable **without** the sticky bit
(`drwxrwxr-x`), which `validate_spool_ancestors_at` correctly rejects. Fixed by
adding `+t` (no permission removed). This run's daemon log contains **zero**
occurrences of that error, so the governance chain-log path was live throughout.

---

## 2. Harness — the shim, and what is first-party

`a2a-mem.sh` is a self-authored bash wrapper around **only** first-party
tooling: the repo's `attest_sign` example (which builds the canonical
`SignableWrite` CBOR envelope using *the same crate code the verifier runs*) and
`curl` against the HTTPS REST surface. No third-party crates, proxies or agents.

The division of labour matters for the validity of the result: **the LLM agent
decides *what* to store and *what* to ask for** — the agentic act — while the
shim performs the fixed Ed25519-signed, mTLS-pinned I/O, exactly as a production
agent runtime signs writes under the hood rather than having a model hand-roll
Ed25519 and deterministic CBOR.

**Harness note (IronClaw, not ai-memory):** IronClaw 1.1.0 refuses to build its
runtime when the process CWD is an ancestor of its reborn-home skill root
(`workspace root must not overlap default skill root /skills`). Both agents are
therefore driven from a sibling `agent-ws/` directory. This is an IronClaw
constraint with no ai-memory involvement.

---

## 3. Enrollment

| Check | Expected | Actual | Verdict |
|-------|----------|--------|---------|
| `/health` over mTLS with allowlisted client cert | 200 | `200`, `status:ok`, `version:1.0.0` | PASS |
| Same request, **no client cert** | refused | `HTTP=000`, curl exit **56** (TLS refused) | PASS |
| `client-bad.crt` — valid CA chain, fingerprint **not** on allowlist | refused | `HTTP=000`, curl exit **56** | PASS |
| `/capabilities` | postgres + AGE | `{"version":"1.0.0","db_schema_version":88,"storage_backend":"postgres","kg_backend":"age"}` | PASS |
| Register `ai:alice` / `ai:bob` | 201 | `201` both | PASS |
| Bind Ed25519 pubkeys as `ai:operator` | 200 | `200` both, `{"bound":true}` | PASS |
| Bind attempted by non-admin `ai:mallory` | 403 | `403 {"error":"admin role required"}` | PASS |

Keys as persisted in postgres (`_agents` namespace) match the on-disk public
keys exactly:

```
title        | agent_pubkey                                 | bound_at
agent:ai:alice | BbXDjX6BVScrAo0Lq1GouIQ0CrpMxGMaIeQOZkzi-_U | 2026-08-09T20:11:42.301552732+00:00
agent:ai:bob   | tkI840eYKLs0HAY5gaSEb4iB4V7kbXe0NHJ-Ix9rCd4 | 2026-08-09T20:11:42.422410153+00:00
```

The mTLS allowlist entry
`0ac0223045d2ab4f18e0d1da80ad878b0171d2cd8605fbf90af905cc54ec4f55` matches the
`openssl` SHA-256 fingerprint of `client-good.crt` byte-for-byte.

---

## 4. Deterministic pre-check (not the agentic act)

Before spending an LLM turn, a manual signed store + cross-agent recall pair was
run with the **raw wire bytes captured verbatim**, specifically to settle the
prior run's ambiguity. Signed store returned `201` with:

```json
"metadata":{"agent_id":"ai:alice","attest_level":"agent_attested",
            "kind_provenance":"channel_derived","scope":"collective",
            "write_signature":"XdXoFgp1/6iruCeSuHmoSetF4m6/Uon4lMJC…"}
```

The recall response shape was then enumerated rather than assumed:

- top-level keys: `count, memories, mode, recall_id, storage_backend, tokens_used`
- `count: 1`, `memories | length: 1`
- row type: **object**; `metadata` keys: `agent_id, attest_level, kind_provenance, scope, write_signature`
- the **exact extraction the prior shim used** returns full values:
  `{"id":"98bcddcf…","title":"precheck-signed-store-192529","content":"deterministic pre-check payload: the canary token is PRECHECK-192529-OK","agent":"ai:alice","attest":"agent_attested"}`

So the shim's jq paths were correct all along; §1 explains the artifact.

---

## 5. Alice — the agentic write

IronClaw (`IRONCLAW_REBORN_HOME=…/ironclaw-alice`, identity `ai:alice`,
`x-ai/grok-4.5`) was told *to invent* an operational fact including a codeword
of its own choosing, and to store it under the title `alice-a2a-handoff`. The
model's chosen content:

```
OP-HANDSHAKE codeword QUASAR-NINE-VELVET: relay window opens 2026-08-09T21:05Z
on channel gamma-7; challenge nonce is 7f3c-a91e-44b2; bob must ack with the
nonce reversed before ingesting the payload at drop point R-17.
```

Alice reported memory id `4fdd4532-c53f-4761-b481-f1fd70eba142`,
`attest_level: agent_attested` — both corroborated by the postgres dump in §8.

---

## 6. Bob — the agentic read (**the A2A assertion**)

A **separate** IronClaw instance (own reborn home, own thread DB, identity
`ai:bob`) was given the title `alice-a2a-handoff` and **nothing about the
content**, plus an explicit instruction never to guess. Bob chose his own query
terms, found the row on his first attempt, and reported:

| Field | Bob reported | Ground truth (postgres) | Match |
|-------|--------------|-------------------------|-------|
| content | `OP-HANDSHAKE codeword QUASAR-NINE-VELVET: … drop point R-17.` | identical | ✅ |
| memory id | `4fdd4532-c53f-4761-b481-f1fd70eba142` | identical | ✅ |
| author | `ai:alice` | `metadata.agent_id = ai:alice` | ✅ |
| attest level | `agent_attested` | `metadata.attest_level = agent_attested` | ✅ |

Because bob was never told the codeword `QUASAR-NINE-VELVET` — which alice's
model invented moments earlier — his verbatim report can only have come out of
the substrate. **B4 PASS.**

---

## 7. Negative assertions

All six run against the same live daemon under `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1`.

| # | Attack | Expected | Actual | Verdict |
|---|--------|----------|--------|---------|
| NEG-1 | Unsigned write as `ai:mallory` (unenrolled) | 403 | `403 ATTESTATION_FAILED` | PASS |
| NEG-2 | Unsigned write as `ai:alice` (**enrolled**, key bound) | 403 | `403 ATTESTATION_FAILED` | PASS |
| NEG-3 | Envelope `agent_id=ai:bob` signed with **alice's** private key | 403 | `403` — *"write signature did not verify against the agent's bound public key"* | PASS |
| NEG-4 | Alice's **genuine** signature replayed under `X-Agent-Id: ai:bob` | 403 | `403` — same | PASS |
| NEG-5 | Valid alice signature, **content swapped** after signing | 403 | `403` — same | PASS |
| NEG-6 | *Positive control:* correctly-signed `ai:bob` write | 201 | `201`, `attest_level=agent_attested` | PASS |

NEG-2 is the assertion that matters most for the ASI posture: **enrollment is
not authorisation.** A bound key does not let an agent write unsigned.
NEG-6 exists so the five refusals cannot be explained away as a broken write path.

**Durability check** — after all six, the only `neg*` row in postgres is
`neg6-positive-control-bob`. **Zero rows** from NEG-1..NEG-5 reached the durable
store: the substrate refused rather than accepting-and-flagging. **B6 PASS.**

---

## 8. Postgres row dump (durable source of truth)

```
                  id                  | agent_id |  attest_level  |            title
--------------------------------------+----------+----------------+------------------------------
 98bcddcf-af6b-4576-99c5-03284bc13703 | ai:alice | agent_attested | precheck-signed-store-192529
 4fdd4532-c53f-4761-b481-f1fd70eba142 | ai:alice | agent_attested | alice-a2a-handoff
 6ee26a49-7d46-4546-a41e-2ec5fbd29479 | ai:bob   | agent_attested | neg6-positive-control-bob
(3 rows)
```

All three carry `scope=collective`, `has_write_signature=t`,
`memory_kind=observation`, `tier=mid`. Namespace census is exactly
`_agents: 2`, `trackb-a2a: 3` — nothing leaked elsewhere.

`alice-a2a-handoff` content in postgres is byte-identical to what alice's model
reported writing and to what bob's model reported reading.

**`signed_events` is empty (0 rows), and that is expected, not a gap.** The
`memory.stored` event type is emitted only by the CLI `verify` substrate writer
(`src/cli/verify.rs`); the ordinary store path emits no `signed_events` row on
*either* backend, so this is not a postgres-parity defect. The per-decision
record for this run lives in the forensic audit chain
(`home/.local/state/ai-memory/audit/forensic-2026-08-09.jsonl`), which captured
all 12 decisions including the `ai:mallory` admin `deny`.

---

## 9. AGE graph projection

Rather than report the graph path as "not exercised", a link was written and
traversed.

| Check | Result |
|-------|--------|
| `POST /links` (alice-handoff → bob-control, `related_to`) | `201`, `attest_level=self_signed`, `linked:true` |
| `GET /links/{id}` | `200`, edge present with `valid_from`, `observed_by=daemon` |
| Relational `memory_links` row | present, **both** `source_cid` and `target_cid` populated (schema v75 lineage mirrors) |
| AGE labels materialised | `memory_graph."Memory"` = **2** vertices, `memory_graph.related_to` = **1** edge |
| Native Cypher over AGE | returns the full `(a)-[r]->(b)` triple with real vertex/edge agtype payloads |
| `POST /api/v1/kg/query` (`source_id`, `max_depth:2`) | `200`, `count:1`, path `4fdd4532…->6ee26a49…`, relation `related_to` |

`kg_backend` self-reports `age` and the HTTP KG read path genuinely traverses
the AGE projection — consistent with the #2792 fix present at this tip.

*Measurement note:* `pg_stat_user_tables.n_live_tup` initially read `0` for the
AGE label tables; that is pre-`ANALYZE` statistics lag, not missing data. Exact
`count(*)` and the Cypher result both confirm 2 vertices / 1 edge.

*Cosmetic observation (no defect filed):* a header-less `GET /links/{id}` logs
`HTTP memory **write** without agent_id … assigned anonymous:req-…` on a read
path. Isolated by a timestamped A/B probe (evidence.log step 8d): the warnings
fire ~11ms after the header-less GET and not at all for the same GET with
`x-agent-id`. The step-9 `POST /links` did carry `x-agent-id: ai:bob` and was
attributed correctly. Shared SSOT resolver message; wording only, no
misattribution.

---

## 10. Honesty ledger — proven vs deferred

### Proven locally, on the certified config

- Agent→agent memory exchange between two independently-driven LLM agents:
  a self-invented secret written by one and read verbatim by the other.
- Ed25519 write attestation end-to-end (`agent_attested`), signature bound to
  `sha256(content)` — content tampering breaks it (NEG-5).
- Identity binding: a signature must verify against **that** agent's bound key;
  neither cross-key signing (NEG-3) nor envelope replay under another principal
  (NEG-4) is accepted.
- Enrollment ≠ authorisation (NEG-2); refusals are durable-write-free (B6).
- mTLS peer gating: cert-less and non-allowlisted peers cannot complete a handshake.
- Admin-route gating: non-admin pubkey bind refused 403 and audited as `deny`.
- Postgres 16 + AGE 1.6.0 + pgvector 0.8.6 substrate at schema v88, with a real
  AGE projection and a working HTTP KG traversal.

### NOT proven here — deferred to the DigitalOcean round

- **Multi-node federated A2A (B8).** PLAN.md's Track B criterion says *"two
  enrolled **daemons** … across the **federation transport**"*. This run used
  **one** daemon; the two agents are two IronClaw **clients** of it. The daemon
  itself logged `durability model: local-single-node (multi-node: false)` and
  `federation_enabled: false`. Quorum replication, peer enrollment, inbound
  write-signature/nonce gates and cross-node convergence are **untested here**
  and belong to the DO multi-node round (Track D's machinery on the DO substrate).
- **Encryption leg 3** (daemon→Postgres `sslmode=verify-full`). Legs 1 and 2
  (API mTLS) are proven; the daemon→PG hop ran over the loopback container link
  without TLS. Track E owns leg 3.
- **Semantic recall over pgvector.** Deliberately out of scope: `tier=keyword`
  was chosen so the A2A proof is deterministic. pgvector is installed and the
  schema provisions `vector(384)`, but no embedding was computed. Track C/E own it.
- **Signed A2A *signals*/*actions*.** The PLAN clause names "signals/actions".
  This run proved memory exchange plus signed writes; the `signals` /
  `actions` coordination tables (schema v59/v60) were **not** exercised.

### Known gap disclosed: #2788 — no MCP-over-HTTP, REST workaround used

ai-memory v1.0.0 exposes MCP `tools/call` **only over stdio**, and
`ai-memory mcp` accepts only `--db` (SQLite) — so the stdio MCP surface cannot
target a Postgres/AGE store at all. The HTTP daemon serves the REST tool surface
plus `GET /api/v1/tools/list` (a parity *view*), but no spec-compliant MCP
Streamable-HTTP/SSE endpoint. IronClaw 1.1.0 registers external MCP servers only
as **hosted HTTP/SSE** endpoints and hard-refuses stdio
(`"stdio MCP transport is unsupported until process-level egress controls
land"`).

**Net: IronClaw cannot natively register ai-memory as an MCP server on any
transport.** Track B therefore drove the **HTTPS REST** surface through
IronClaw's generic `builtin.bash` tool. This is a faithful test of the wire
surface, attestation and governance, but it is **not** native MCP tool
discovery: the agents never saw ai-memory's tools in their MCP catalog, and each
operation is a hand-wired HTTP call rather than a model-selected tool. Any claim
that "IronClaw uses ai-memory as an MCP server" would be false at v1.0.0.

---

## 11. Reproduction

```bash
R=.local-runs/cert-campaign/trackb/rerun-2026-08-09
bash $R/01-provision.sh                 # fresh trackb_a2a + schema-init (v88 + AGE)
nohup bash $R/02-boot-daemon.sh &       # mTLS + attestation-strict daemon on :19555
bash $R/03-enroll.sh                    # health, mTLS negatives, register + bind keys
bash $R/04-precheck.sh                  # deterministic signed store + recall, raw bytes
bash $R/04b-prior-artifact-forensics.sh # what the 2026-08-08 all-null row actually was
bash $R/05-alice.sh                     # ALICE agentic write  (IronClaw + Grok 4.5)
bash $R/05b-bob.sh                      # BOB   agentic read   (separate instance)
bash $R/06-negatives.sh                 # NEG-1..NEG-6 + durability check
bash $R/07-pg-dump.sh                   # verbatim postgres row dump
bash $R/08-age-and-audit.sh             # link + AGE Cypher + forensic audit chain
```

Each is invoked through `$R/ev.sh "<label>" <cmd>`, which appends the label,
UTC timestamp, exact command, verbatim output and exit code to `evidence.log`.

---

## 12. Issues

**No new defects filed by this track.** Three candidate findings were run down
and each resolved to a non-defect on evidence:

1. The 2026-08-08 all-null recall row → superseded-shim reporting artifact over
   a correctly-empty result set (§1).
2. Empty `signed_events` after three attested writes → expected on both
   backends; the ordinary store path emits no such row (§8).
3. `anonymous:req-*` warnings during the link step → emitted by a header-less
   read probe, not by the attributed `POST /links` (§9).

Pre-existing, previously filed, and re-confirmed here: **#2788**
(no MCP-over-HTTP endpoint) — see §10.
