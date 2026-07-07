# v0.9.0 — DigitalOcean crypto-hardened operational evidence

> **Status: 3 CONSECUTIVE GREEN ROUNDS — all encryption over verified TLS.**
> A live DigitalOcean droplet (NYC3, `s-1vcpu-2gb`, id 582767938) provisioned
> by the **fixed** `cloud-init-memory.yaml.tpl` ran the full crypto suite for
> **3 consecutive green rounds (17/17 assertions each)** — the three encryption
> legs each proven positive **and** negative, agent attestation on with a real
> bound keypair, and semantic pgvector recall end-to-end. Torn down to **zero**
> droplets immediately after (3 destroyed). This round replaces the earlier
> plaintext/attestation-off DO round, which validated no crypto.

## Caveat 3 — fixed cloud-init validated

Round 1 (the yanked release) got a **bare droplet**: a U+0080 char broke the
cloud-config YAML so nothing provisioned. After the #1880 fix (+ CI ASCII
gate), this provision came up clean: `cloud-init status --long` →
`extended_status: done` (not `degraded`), **PostgreSQL 16.14 + Apache AGE
1.6.0 + pgvector 0.6.0** installed automatically, `aimemory` db present. The
automated provisioning path works.

## The 3 encryption legs — each positive + negative, ×3 rounds

Tooling: `infra/do-hive/crypto/` (`gen-certs.sh` + per-leg pos/neg runners,
committed `e5939fec`). Binary: tip `8c8bc174` built `--release --features
sal,sal-postgres` (post-#1882; version 0.9.0), deployed to the droplet.

| Leg | Assertions | Result (all 3 rounds) |
|-----|-----------|------------------------|
| **1 — API mTLS** (client↔daemon) | POS: allowlisted client-good → 200. NEG1: no cert → TLS refused (curl 56, `client_auth_mandatory`). NEG2: unlisted-fingerprint cert (same CA) → refused — proves the SHA-256 **pin** is the anchor, not the CA. | **3/3 PASS** |
| **2 — Federation/quorum mTLS** (daemon↔peer, W=2) | POS1: authorised peer reaches peer over mTLS (200). POS2: quorum write carried over the mTLS mesh. NEG1: unauthorised peer cert → refused. NEG2: plaintext peer → refused. | **4/4 PASS** |
| **3 — daemon→Postgres `verify-full`** | POS: `sslmode=verify-full` + pinned CA connects (real daemon served /health over it). NEG1: plaintext (`sslmode=disable`) → refused (hostssl-only pg_hba). NEG2: host-mismatch cert → refused. NEG3: unpinned/invalid CA → verify failed. | **5/5 PASS** |

## Attestation (#1751) + semantic recall (caveat 2)

| Check | Result |
|-------|--------|
| **Attestation** — real bound Ed25519 keypair; signed write (canonical `attest_sign` envelope) accepted **201**; unsigned write rejected **403 `ATTESTATION_FAILED`** | **2/2 PASS** |
| **Semantic pgvector recall** — in-process MiniLM-384; `<=>` cosine recall returns ranked hits; a paraphrase with no shared keywords ranks the semantic match #1 | **3/3 PASS** |

**Per round: 17/17. Three consecutive rounds: GREEN.**

## Operational notes / findings (no product bug)

All issues were config/build/usage, documented in `infra/do-hive/crypto/README.md`:
1. **`AI_MEMORY_NO_CONFIG=1`** — escapes an operator config's `db`/tier, pins
   tier=semantic → in-process MiniLM-384. `serve` has no `--tier` flag.
2. **`--db`/`--store-url` mutual exclusion** vs a config `db` field is what
   made the *first* DO round's `serve` refuse to bind — solved by `NO_CONFIG`.
3. **`initdb` refuses to run as root** — the pg-TLS leg runs as the `postgres`
   user on the droplet.
4. The DO binary must be tip `8c8bc174` built `--features sal,sal-postgres`
   (post-#1882); the `latest` release predates the fix.

## Teardown

`teardown.sh` → **3 destroyed** (droplet + firewall + VPC), `doctl compute
droplet list` → empty. Zero residual spend.
