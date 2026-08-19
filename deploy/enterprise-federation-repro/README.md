<!--
Copyright 2026 AlphaOne LLC
SPDX-License-Identifier: Apache-2.0
-->
# enterprise-federation-repro

The **100%-reproducible enterprise-federation audit/test environment kit**. It
stands up the EXACT substrate the v1.0.0 enterprise-federation audit used, so
any AI NHI (or human peer reviewer) can reproduce it from committed steps and
re-run the **3x7 audit scheme**.

The full, narrated walkthrough — provisioning, certificates, corpus, config,
wiring, the 3x7 method, and the honest caveats — is the GitHub-Pages page:
**`docs/compliance/enterprise-federation-repro.html`**
(<https://alphaonedev.github.io/ai-memory-mcp/compliance/enterprise-federation-repro.html>).
This README is the operator quick-reference.

## What it stands up

- **Data tier** — PostgreSQL **18.6** + Apache AGE **1.8.0** + pgvector **0.8.6**
  (the pins are SOURCED from `deploy/docker-1461/provision/lib.sh`; the image is
  built from the canonical `deploy/docker-1461/Dockerfile.pg-age-vector`). TLS
  1.3, **hostssl-only** (cleartext refused pre-auth), **client-cert mTLS** to
  the store.
- **ai-memory** wired into ONLY that tier over the encrypted store link
  (`sslmode=verify-full` + client cert), served on the client↔daemon **mTLS**
  API (`:9077`) under the **certified enterprise-federation posture**.
- **Deterministic seed corpus** (portable synthetic stand-in for the audit's
  7,855-row Atlas corpus), loaded via `ai-memory migrate`.

## Layout

| File | Role |
|---|---|
| `lib.sh` | SSOT constants + helpers; **inherits** the PG/AGE/pgvector pins from `deploy/docker-1461/provision/lib.sh` (never re-declares them). |
| `gen-certs.sh` | Mints the CA + PG server/client certs (store leg) + daemon server + `client-good` cert + `allowlist.txt` (API leg). No secrets committed. |
| `initdb/01-extensions.sql` | First-boot `CREATE EXTENSION age; CREATE EXTENSION vector;`. |
| `initdb/pg_hba.conf` | hostssl-only + `clientcert=verify-full` client-auth map. |
| `seed-corpus.sh` | Deterministic synthetic corpus → local sqlite seed DB. |
| `repro.sh` | One-command idempotent standup: stack → certs → keys → schema-init → seed → migrate → certified daemon. |
| `verify.sh` | Proves every invariant with real output (versions, TLS, cleartext-refused, posture, audit trail, recall). |

## Quick start

```bash
# Prereqs: docker (or podman), openssl, curl, cargo (only if no prebuilt binary).
# All scratch lands under .local-runs/ef-repro/ (gitignored; never /tmp).

deploy/enterprise-federation-repro/repro.sh      # stand it up
deploy/enterprise-federation-repro/verify.sh     # prove the invariants
```

Point at a prebuilt binary (must be built `--features sal,sal-postgres,sqlcipher`)
with `AI_MEMORY_BIN=/path/to/ai-memory`. Every knob is env-overridable
(`EF_REPRO_*`); see `lib.sh`.

**Host networking (`-p` DNAT bug).** `repro.sh` publishes the PG tier with
`-p 127.0.0.1:$PG_PORT:5432` by default. Some hosts have a broken docker
`DOCKER` iptables nat chain where port publishing fails (`iptables: No
chain/target/match by that name` / "Unable to enable DNAT rule"). On that
failure the kit AUTO-FALLS-BACK to `--network host` (postgres bound
loopback-only on `$PG_PORT`; the hostssl + client-cert mTLS enforcement and the
daemon's `sslmode=verify-full` dial to `127.0.0.1:$PG_PORT` are byte-identical).
Force either mode with `EF_REPRO_PG_NETWORK_MODE=host|bridge|auto` (default
`auto`). A sqlcipher-built binary (the required feature set) also needs a local
passphrase for the seed/migrate/serve sqlite opens — the kit mints and threads
it (`--db-passphrase-file`) automatically.

## Wiring an AI NHI

The certified daemon speaks the mTLS HTTP API on `:9077`:

```bash
RUN=.local-runs/ef-repro
curl --cacert   "$RUN/tls/ca.crt" \
     --cert     "$RUN/tls/client-good.crt" \
     --key      "$RUN/tls/client-good.key" \
     -H 'X-Agent-Id: ai:cert-fed-proxy' \
     https://127.0.0.1:9077/api/v1/stats
```

## Honest caveats (see the Pages page §caveats)

- **Embedder** — the audit used the local all-MiniLM-L6-v2 (384-d) embedder
  under loopback-only egress. The seed rows carry only durable TEXT; the daemon
  re-derives embeddings at serve-boot. On a machine with no pre-staged model,
  semantic recall **degrades loudly to keyword** — a DEGRADE, never wrong
  results.
- **Schema placement (#3055)** — an unqualified `CREATE TABLE` lands in
  `ag_catalog` if it precedes the app schema; the store DSN pins `public` first.
- **At-rest (#3061)** — the certified posture's at-rest control is the sqlcipher
  build + `AI_MEMORY_ENCRYPT_AT_REST=1`; encrypting the durable memory ROWS in
  the postgres tier is the **PG tier's job** (disk / tablespace / pgcrypto).
- **verify-audit-trail** — the append-only chain + witness + role-separation
  lanes verify with the keys `repro.sh` enrolls; the asi-hard identity-lineage
  require-mode needs a genesis succession record enrolled (a tracked follow-up).

Part of the enterprise-federation audit remediation (epic #3076; issue #3078).
