---
layout: doc
---
# v1.0.0 Enterprise-Certification Test Campaign — PLAN

**Campaign date:** 2026-08-08
**Base commit (cert tip):** `715cb38f` on `release/v1.0.0`
**Status:** LOCKED plan. Local-first (free) proves green, then the identical
config is re-hosted on DigitalOcean for real federated multi-node + capacity.

This document is the clearly-defined, versioned campaign that supersedes the
earlier narrow "USL probe" framing (operator directive 2026-08-08). The DO
droplet round is redefined into the **certified-enterprise-federated test**:
ai-memory v1.0.0 on PostgreSQL 16 + Apache AGE 1.6.0 + pgvector, multi-node
federated, driven by IronClaw + Grok 4.5, exercising AI NHI + A2A + full-spectrum
encryption (3 legs) + E2E + 100% regression. **All channels encrypted,
attestation ON everywhere.** The earlier plaintext + attestation-off round was
declared INVALID and is not part of this campaign.

---

## 1. Config (LOCKED)

| Facet | Locked value |
|-------|--------------|
| Binary | ai-memory **v1.0.0 @ `715cb38f`**, built `cargo build --release --features sal,sal-postgres` |
| Dim-fix | MUST include **#1882** (the postgres `tier=semantic` 768-vs-384 dim fix; commit `9525f450`). A binary without it opens the postgres schema at the wrong vector dim and every write 503s / recall returns empty. See `infra/do-hive/crypto/README.md` for the exact failure mode. |
| Store | **PostgreSQL 16** + **Apache AGE 1.6.0** (tag `release_PG16_1.6.0`) + **pgvector** |
| Schema | **v88** — `CURRENT_SCHEMA_VERSION` SSOT in `src/storage/migrations.rs` + `src/store/postgres.rs::migrate_v88()` at the cert tip. Parity-gated: the sqlite and postgres ladders share the one logical schema number and the campaign asserts sqlite↔postgres schema parity. (This value is the live SSOT at `715cb38f`; the campaign brief's "v81" pre-dated this tip and is superseded — use v88.) |
| AI NHI brain | **Grok 4.5**. xAI-direct: `XAI_API_KEY`, base URL `https://api.x.ai/v1`, model `grok-4.5`. OpenRouter alt: `OPENROUTER_API_KEY`, model `x-ai/grok-4.5`. Backend selection logic is unchanged from prior rounds — only the model id moved to 4.5. |
| Encryption | **ON everywhere** — API mTLS (leg 1), federation/quorum mTLS (leg 2), daemon→Postgres `sslmode=verify-full` (leg 3). |
| Attestation | **ON everywhere** — `AI_MEMORY_REQUIRE_AGENT_ATTESTATION` strict on the store path; federation write-sig (`AI_MEMORY_FED_REQUIRE_WRITE_SIG`) at its v1.0.0 default-ON. |

Two viable encrypted brain-transport paths are both in scope: xAI-direct (the DO
substrate agent runs `grok-4.5` against `api.x.ai/v1`) and OpenRouter
(`x-ai/grok-4.5`, the lan-parity IronClaw containers). The ai-memory daemon's own
LLM/embedder egress is orthogonal to the IronClaw driver's egress.

---

## 2. Tracks

Each track has a concrete pass criterion and is grounded in an existing harness
in this repository. A track is GREEN only when every listed assertion is GREEN
against the LOCKED config above.

| Track | Scope | Harness | Pass criterion |
|-------|-------|---------|----------------|
| **A** | NHI dogfood P0-P11 | `docs/v1.0.0/nhi-playbook-P0-P11.md` (this campaign's versioned playbook) | Every phase P0-P11 SHIP per its own pass assertion; final verdict rubric = SHIP. Exercised MCP/HTTP/CLI against the v1.0.0 binary. |
| **B** | A2A multi-agent | IronClaw + Grok 4.5 two-daemon mesh (lan-parity `ic-parity-alice` ↔ `ic-parity-bob`, then DO multi-node) | Two enrolled daemons exchange signed A2A signals/actions across the federation transport; cross-agent memory visible per governance; no unsigned authority-write accepted. |
| **C** | pg+AGE+pgvector + full regression | `infra/lan-parity-test/run-parity-tests.sh` | `cargo test --features sal,sal-postgres --release` GREEN against the live PG16+AGE 1.6.0+pgvector container on `127.0.0.1:15432`. postgres-backed `live_*` tests are gated on `AI_MEMORY_TEST_POSTGRES_URL` (self-skip when unset); the `#[ignore]`-marked tests require `-- --include-ignored` (see execution note below). Actual live-test count + pass rate recorded in the run log under `.local-runs/`. sqlite↔postgres SAL parity asserted. |
| **D** | Federation | Enrolled multi-node quorum (lan-parity 2-node → DO N-node) | A W-of-N quorum write commits locally AND replicates to the peer over the mutually-authenticated channel; peer-enrollment + write-sig + nonce + policy-current gates all default-ON and satisfied by REAL enrollment (not an escape hatch). |
| **E** | Encryption — 3 legs, pos + neg | The 6 scripts in `infra/do-hive/crypto/` (see §2.1) | Every leg's positive assertion PASSES and every negative assertion is REFUSED (fail-closed). `run-all-local.sh` exits 0 (all legs green). |
| **F** | USL capacity, crypto-ON | DO N-node hive under the encrypted+attested config (`infra/do-hive/`) | Capacity measured on the certified config (encryption + attestation ON) — NOT the earlier invalidated plaintext/attestation-off run. Reported against the defined unit + measured cells (per the operator's 500-1000-agent-cluster / 500-agent-block certification scope). |
| **E2E** | End-to-end | The full chain: IronClaw(Grok 4.5) → encrypted API → ai-memory daemon → PG16/AGE/pgvector, federated, attested | A store→recall→reflect→consolidate→federate round-trip completes with encryption + attestation ON at every hop and the durable memory TEXT intact on both nodes. |

### 2.1 Track E — the 3 encryption legs (exact pos/neg assertions)

Grounded in `infra/do-hive/crypto/` (read its `README.md` for the per-leg serve
invocations). Every script prints PASS/FAIL per assertion and exits non-zero if
any assertion FAILs. `run-all-local.sh` regenerates certs then runs all six legs.

**Leg 1 — API mTLS** (`test-api-mtls.sh`)
- POS: an allowlisted `client-good` cert GETs `/api/v1/health` → `200`.
- NEG1: a client presenting NO client cert cannot complete the TLS handshake (mTLS mandatory).
- NEG2: a valid-but-UNLISTED `client-bad` cert is refused at the rustls `ClientCertVerifier` (daemon logs `not in mTLS allowlist`).

**Leg 2 — federation / quorum mTLS** (`test-federation-mtls.sh`, W-of-N = 2)
- POS1: peerA's authorised client cert to peerB's federation endpoint over HTTPS → `200`.
- POS2: a W=2 quorum write to peerA commits locally AND replicates to peerB (`201 quorum_met`, or `202` locally-durable if the ack lands late).
- NEG1: an UNAUTHORISED peer (`client-bad`, not on the allowlist) is refused at peerB's TLS layer (connection cannot open).
- NEG2: a PLAINTEXT peer (`http://` to the mTLS port) is refused.

**Leg 3 — daemon→Postgres `sslmode=verify-full`** (`test-pg-verifyfull.sh`)
- POS: `sslmode=verify-full` + `sslrootcert=ca.crt` against `host=localhost` (matches the cert SAN) CONNECTS with full server-cert verification.
- NEG1: `sslmode=disable` (plaintext) is REFUSED — `pg_hba` is `hostssl`-only.
- NEG2: `sslmode=verify-full` against `host=127.0.0.1` (NOT in the cert SAN) is REFUSED on the hostname check.
- NEG3: `sslmode=verify-full` with an UNRELATED CA as `sslrootcert` is REFUSED on chain verification.

**Attestation** (`test-attestation.sh`, #1751)
- POS: a signed write (the `attest_sign` example envelope + the bound Ed25519 key) is accepted `201` and the stored row carries `metadata.attest_level = "agent_attested"`.
- NEG: an UNSIGNED write is rejected `403` with code `ATTESTATION_FAILED`.

**Federation write-signature cross-peer attestation** (`test-fed-write-sig-attestation.sh`, #1801→#1954 default-on flip; #1937 spawn-audit; #1947 FED-RQ-03)
- POS: a SIGNED write authored as `ai:alice` on peerA federates to peerB and reaches `attest_level=agent_attested` at peerB (queried over peerB's HTTP API) — proves EMIT + cross-peer author enrollment + the strict flip together.
- NEG: an UNSIGNED third-party relay (author `ai:mallory`, no key enrolled at peerB) is REFUSED at peerB's receiver (fail-closed) — the row never lands, peerB logs the write-sig WARN + DLQ cause `unenrolled_author_strict`.
- AUD: the daemon emits SIGNED `process.spawn_audited` events (#1937), verified via `ai-memory verify-audit-trail` / a `signed_events` query.
- POL: FED-RQ-03 (#1947) policy-current gate is default-ON and fail-closed for a DETECTED-stale peer while fail-OPEN for equal/absent policy (both nodes at `policy_seq=0`), so existing federation is not bricked.

**Semantic recall** (`test-semantic-recall.sh`, caveat 2)
- Stores three topically-distinct memories, then recalls with a PARAPHRASE sharing no salient keywords with the target; asserts the semantic hit ranks first and the response `mode` is `hybrid` (a real embedding vector component was produced). Optional `STORE_URL` points at the pgvector store to prove the real `<=>` operator path on the DO substrate. Uses the in-process MiniLM-L6-v2 (384-dim candle) embedder — no Ollama/nomic dependency.

---

## 3. Execution model

**Local-first, then DO — one observable orchestration.**

1. **Local (free) proves green.**
   - Crypto legs: `infra/do-hive/crypto/run-all-local.sh` (regenerates certs, runs all six legs, non-zero exit if any leg fails).
   - pg+AGE+pgvector + regression: bring up `infra/lan-parity-test/docker-compose.yml` (PG+AGE 1.6.0+pgvector container + 2 IronClaw daemons), then `infra/lan-parity-test/run-parity-tests.sh`.
   - This entire local stage costs $0 (Docker on the local node + in-process MiniLM embedder).
2. **DO re-hosts the identical config** for the parts local cannot prove: real federated multi-node reachability across droplets, and capacity (Track F) at cluster scale. The DO substrate (`infra/do-hive/`) is provisioned with the byte-identical AGE 1.6.0 pin and Grok 4.5 wiring so a result proven locally is proven on DO.
3. **One observable orchestration.** Each phase writes a per-phase log under `.local-runs/`; teardown is trap-guarded (`infra/do-hive/teardown.sh` is idempotent; the crypto legs trap-clean their temp dirs). No synchronized-blast defaults; the DO hive is paced and money-gated (operator-triggered spend only).

**Execution notes (surfaced findings, not deferrals):**
- `run-parity-tests.sh` as shipped runs `cargo test --features sal,sal-postgres --release` WITHOUT `-- --include-ignored`, so the `#[ignore]`-marked postgres tests are NOT exercised by it. The cert run MUST additionally invoke the suite with `-- --include-ignored` (or extend the script) to cover those, and the run log records both invocations. This is a Track C coverage item to close during execution.
- The DO substrate binary MUST be the #1882-fixed `sal-postgres` build; the memory droplet's `serve` unit only starts once such a binary is present (`infra/do-hive/cloud-init-memory.yaml.tpl`).

---

## 4. Certification gaps being closed (6)

The campaign exists to close six concrete reproducibility / coverage gaps that
stood between "CI is green" and "enterprise-certified":

1. **Enrolled-federation happy-path never smoke-tested LIVE.** The mechanism to
   auto-provision peer-key cross-enrollment now EXISTS at this tip
   (`infra/lan-parity-test/docker-compose.yml` ships the one-shot
   `ic-parity-peer-key-provisioner` service + `provision-peer-keys.sh`, #1803),
   so a bare `docker compose up` yields a WORKING enrolled mesh — but the
   enrolled happy-path had not been exercised end-to-end and recorded as cert
   evidence. This campaign runs it LIVE (Track D) and captures the evidence.
2. **P0-P11 playbook was memory-only.** The NHI dogfood playbook lived solely as
   a stored memory (a reproducibility gap). It is now committed as the versioned
   doc `docs/v1.0.0/nhi-playbook-P0-P11.md` (Track A).
3. **AGE version was unpinned on DO.** `infra/do-hive/cloud-init-memory.yaml.tpl`
   is pinned to the exact tag `release_PG16_1.6.0`, version-identical to
   `infra/lan-parity-test/Dockerfile.pg-age-vector` (`apache/age:release_PG16_1.6.0`),
   so DO and lan-parity run the same AGE build.
4. **Chaos was a manual runbook.** Phase P11 (failure/chaos, fail-closed) is a
   first-class track phase with concrete pass assertions rather than an ad-hoc
   manual runbook.
5. **Production embedder under-exercised over pgvector.** Track E's
   `test-semantic-recall.sh` with `STORE_URL` set drives the real pgvector `<=>`
   path; Track C exercises the sal-postgres embedding column end-to-end with the
   #1882 dim-fix.
6. **Unified cert-runner being built.** The local-first orchestration
   (crypto `run-all-local.sh` + lan-parity `run-parity-tests.sh` + the P0-P11
   playbook) is the seed of the single cert-runner; this PLAN is its
   specification.

---

## 5. Prerequisites / open dependency

- **IronClaw artifact (operator-provided).** Pinned to **v1.1.0** (`nearai/ironclaw`,
  tag `ironclaw-v1.1.0`, released 2026-08-06). The previously-pinned
  `github.com/alphaonedev/ironclaw` v0.28.1 URL is dead/unreachable and has been
  replaced across the infra (`infra/do-hive/main.tf`, `infra/aws-gpu-burst/main.tf`,
  and both agent cloud-init Descriptions). IronClaw 1.1.0 is the "Reborn" runtime,
  a complete re-architecture: the obsolete v0.28.1 `--provider` / `--base-url` /
  `--model` CLI flags do NOT exist in 1.1.0 (it is config-driven —
  `ironclaw onboard` + `models set-provider` + `config set` secrets). The
  DO agent cloud-init `ExecStart` invocation line is therefore left AS-IS for now;
  the correct 1.1.0 Reborn-runtime invocation replaces the obsolete flags and is
  being validated separately, wired in a follow-up commit. This is an
  operator-provided dependency (an authorized, public test-driver artifact), NOT a
  shirked task.

---

## 6. Verdict gate

The campaign mints **SHIP** only when every track (A-F + E2E) is GREEN under the
LOCKED config, every crypto leg's pos + neg assertions hold, the DO re-host
reproduces the local green, and every finding surfaced during execution is
filed + fixed + retested (per the repo prime directive — no deferrals, no
surface-level dismissals). Any track RED, or any negative-assertion that is NOT
refused, blocks the verdict.
