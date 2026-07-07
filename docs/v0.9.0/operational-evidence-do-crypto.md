# v0.9.0 — DigitalOcean crypto-hardened operational evidence

> **Status: 3 CONSECUTIVE GREEN ROUNDS on the FULLY-HARDENED binary — all
> encryption over verified TLS.**
> A live DigitalOcean droplet (NYC3, `s-1vcpu-2gb`, id **582930734**,
> 159.65.254.58 / private 10.20.0.2) provisioned by the **fixed**
> `cloud-init-memory.yaml.tpl` ran the full crypto suite for **3 consecutive
> green rounds (17/17 assertions each)** against the **fully-hardened release
> binary** — tip **`65772202`** (`release/v0.9.0`, all 49 hardening findings
> fixed), sha256 `d6d0d2e3c9cf77522791e787d7f2e12ca4996ceee213291fc1f8104e72ae470b`,
> built `--release --features sal,sal-postgres` (+ the `attest_sign` example).
> Every SSH/scp channel was encrypted; the daemon↔client, daemon↔peer, and
> daemon↔Postgres links were all TLS. Torn down to **zero** droplets immediately
> after (3 destroyed). This is the authoritative crypto round; it supersedes the
> earlier `8c8bc174` run.

## Provisioning — fixed cloud-init validated (minimum footprint)

Provisioned via `infra/do-hive/spawn.sh apply` with `TF_VAR_agent_count=0` —
**one memory droplet, no agent droplets** (the minimum for a DO-parity crypto
round). `cloud-init status --long` → `extended_status: done` (not `degraded`);
`/opt/ai-memory/provision.sh` installed **PostgreSQL 16.14 + Apache AGE 1.6.0 +
pgvector 0.6.0** automatically (AGE built from source against pg16), created the
`aimemory` db and both extensions:

```
 extname | extversion
---------+------------
 vector  | 0.6.0
 age     | 1.6.0
```

The stale `latest`-release binary the cloud-init tarball fetched was stopped
(`systemctl stop/disable ai-memory`); every assertion below runs the **scp'd
hardened `65772202` binary** (sha256 verified equal on both ends).

## The 3 encryption legs — each positive + negative, ×3 rounds

Tooling: `infra/do-hive/crypto/` (`gen-certs.sh` + per-leg pos/neg runners).
Cert SANs include the droplet substrate (`EXTRA_SAN_IP=159.65.254.58`).

| Leg | Assertions (real output) | Result (all 3 rounds) |
|-----|--------------------------|------------------------|
| **1 — API mTLS** (client↔daemon) | POS: allowlisted client-good `GET /health` → **200**. NEG1: no client cert → TLS refused (**curl exit 56**, `client_auth_mandatory`). NEG2: unlisted-fingerprint cert (same CA) → refused (**curl exit 56**) — proves the SHA-256 **pin** is the anchor, not the CA. | **3/3 PASS** |
| **2 — Federation/quorum mTLS** (daemon↔peer, W=2) [#1920/#1928] | POS1: authorised peerA client cert reaches peerB over mTLS (**200**). POS2: W=2 quorum write carried over the mTLS mesh (**202** locally-durable). NEG1: unauthorised `client-bad` peer → refused at peerB TLS (**curl exit 56**). NEG2: plaintext `http://` peer → refused (**curl exit 1**). | **4/4 PASS** |
| **3 — daemon→Postgres `verify-full`** (DO-only a, run as `postgres` user) | POS: `sslmode=verify-full` + pinned CA + `host=localhost` connects. NEG1: plaintext (`sslmode=disable`) → refused (`no pg_hba`, hostssl-only). NEG2: host-mismatch → refused (`certificate for "localhost" (and 1 other name) does not match host`). NEG3: unpinned/other CA → refused (`certificate verify`). **EXTRA**: the real hardened daemon connected over verify-full TLS and served `/health`. | **5/5 PASS** |

## Attestation (#1919/#1931)

| Check | Real output | Result |
|-------|-------------|--------|
| **Attestation** — real bound Ed25519 keypair; signed write (canonical `attest_sign` envelope) accepted **201** (e.g. round-1 id `f1b1cb1b-71d5-4192-8da7-5164b8838764`); unsigned write rejected **403 `ATTESTATION_FAILED`** | `PASS: attest POS: signed write accepted 201` / `PASS: attest NEG: unsigned write rejected 403 ATTESTATION_FAILED` | **2/2 PASS** |

## DO-only coverage the local harness could not exercise

These three items are proven **only** on the real DO PostgreSQL substrate; each
was green in all 3 rounds.

**(a) leg-3 `verify-full` on the droplet substrate as the `postgres` user** —
`initdb` refuses root, so the ephemeral TLS cluster + the verify-full matrix run
as `postgres`. Positive (verify-full + pinned CA connects, **real daemon serves
`/health` over verify-full TLS**) + all three negatives (plaintext /
host-mismatch / bad-CA refused). See leg 3 above — **5/5 PASS** each round.

**(b) NON-EMPTY `signed_events` cross-row chain with the audit trail ENABLED**
[#1925/#1930] — 4 real `coordination.signal_send` audit rows generated via the
MCP full profile (`AI_MEMORY_PROFILE=full` → `memory_signal_send`), then:

```
INFO: generated 4 coordination.signal_send signed_events rows
PASS: signed-events POS: non-empty (4 rows) cross-row chain verifies green
      [verify-signed-events-chain OK: 4 row(s) walked, chain holds]        # exit 0
PASS: signed-events NEG: tampered row seq=2 -> chain break, verify exit 1
      [verify-signed-events-chain FAIL: chain break at sequence=3 (4 row(s) walked)]
```

Tampering one row's `payload_hash` breaks the chain and `verify-signed-events-chain`
**fails closed (exit 1)** — the tamper-evidence guarantee holds on the substrate.
**2/2 PASS** each round.

**(c) semantic pgvector recall over the REAL Postgres `<=>` operator via
`STORE_URL`** — `STORE_URL=postgres://aimemory:***@localhost:5432/crypto_sem_rN?sslmode=require`
(daemon→Postgres over **TLS**). Daemon boot log:

```
embedder loaded (all-MiniLM-L6-v2 (384-dim, local)) — tier=semantic semantic recall enabled
Wave-3 (issue #877): opening Postgres SAL store at
  postgres://aimemory:****@localhost:5432/crypto_sem_rN?sslmode=require
  (statement_timeout=30s, embedding_dim=384, auto_migrate=on, ...)
PASS: semantic: recall mode='hybrid' (embedder produced a real vector component)
PASS: semantic: paraphrase (no shared keywords) ranked the k8s memory #1 -> real MiniLM-384 <=> similarity
PASS: semantic: daemon log confirms MiniLM/384-dim embedder (MiniLM-L6-v2)
```

Stores land **201** on the postgres store; a paraphrase sharing no keywords with
the target ranks the semantic match #1 through the real pgvector `<=>` operator.
**3/3 PASS** each round.

## Per-round tally

Every round: **17/17** core assertions green (leg1 3 + leg2 4 + leg3 4 + attest 2
+ semantic 2 + signed-events 2), plus two bonus corroborations (leg-3 EXTRA real
daemon `/health` over verify-full; semantic MiniLM-384 log confirmation). Each
round exited **0**.

```
############ ROUND 1 RESULT ############  ROUND 1: ALL LEGS GREEN (17/17)   exit 0
############ ROUND 2 RESULT ############  ROUND 2: ALL LEGS GREEN (17/17)   exit 0
############ ROUND 3 RESULT ############  ROUND 3: ALL LEGS GREEN (17/17)   exit 0
```

**Three consecutive rounds on the hardened `65772202` binary: GREEN.**

## Operational notes / findings (no product bug)

All issues were config/build/usage, documented in `infra/do-hive/crypto/README.md`:
1. **`AI_MEMORY_NO_CONFIG=1`** pins tier=semantic → in-process MiniLM-384 (no
   `--tier` flag on `serve`).
2. **`initdb` refuses root** — the pg-TLS leg runs as the `postgres` user; its
   verify-full daemon needs a postgres-writable cwd for the sqlite coordination
   sidecar (`app.db`) to bind and serve `/health`.
3. **`signed_events` coordination rows** are emitted by the MCP coordination
   tools (`memory_signal_send`, …), which require `AI_MEMORY_PROFILE=full`; the
   HTTP `/signals` route and the CLI `link` do **not** append to the V-4 chain.
4. The DO binary must be built `--features sal,sal-postgres` (post-#1882,
   384-dim schema); the `latest` release predates the hardening tip.
5. **`teardown.sh`** requires `TF_VAR_ssh_pubkey_fingerprint` to be exported
   (the `main.tf` variable has no default) or `terraform destroy` refuses.

## Teardown

`teardown.sh` (with `TF_VAR_ssh_pubkey_fingerprint` set) → **3 destroyed**
(droplet 582930734 + firewall 3fb6d1f6 + VPC 4692bc4b); `doctl compute droplet
list` → **empty (0 residual droplets)**. Zero residual spend.
