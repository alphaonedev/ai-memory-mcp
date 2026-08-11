# crypto/ — v0.9.0 crypto-hardened DigitalOcean round tooling

Reusable tooling to provision + exercise the **3 encryption legs + attestation +
semantic recall** the v0.9.0 DO round must prove. Every script runs LOCALLY (free)
first; the DO step re-hosts the identical config onto droplets.

> **Binary requirement.** Build from the current tip **with the postgres features**:
> `cargo build --release --features sal,sal-postgres`. The default build has NO
> postgres adapter (`--store-url postgres://` is rejected). The binary MUST include
> the #1882 fix (commit `9525f450`, in tip `8c8bc174`) or a `tier=semantic` deploy
> opens its postgres schema at 768-dim while the MiniLM embedder produces 384-dim →
> every write 503s and recall returns empty.

## Scripts

| script | proves |
|--------|--------|
| `gen-certs.sh` | CA + server/client/peer/pg leaf certs, SANs, allowlists, fingerprints |
| `test-api-mtls.sh` | **Leg 1** API mTLS: allowlisted client operates API / no-cert + unlisted-cert refused |
| `test-federation-mtls.sh` | **Leg 2** federation quorum mTLS across 2 local daemons: authorised peer replicates / unauthorised + plaintext refused |
| `test-pg-verifyfull.sh` | **Leg 3** daemon→Postgres `sslmode=verify-full`: pinned-CA connect / scram-sha-256 + `channel_binding=require` connect (guards the RSA cert chain — Ed25519 aborts channel binding) / plaintext + host-mismatch + unpinned-CA refused |
| `test-attestation.sh` | attestation ON (`#1751`): signed write (real bound keypair) accepted / unsigned rejected 403 |
| `test-semantic-recall.sh` | caveat 2: in-process MiniLM-384 vectors + semantic recall ranking (no Ollama/nomic) |
| `run-all-local.sh` | regenerates certs + runs every leg; non-zero exit if any fails |

## Cert generation

```bash
# localhost-only material:
./gen-certs.sh
# add the DO substrate SANs (private IP the daemon binds + the PG host in the URL):
EXTRA_SAN_IP=10.20.0.5 EXTRA_SAN_DNS=hive-substrate PG_HOST=10.20.0.5 ./gen-certs.sh
```
Output in `./out/`. The mTLS verifier pins `SHA-256(client-cert DER)` (SSH
known_hosts model, CA chain ignored), so `allowlist.txt` = `sha256(client-good DER)`.

## The exact serve invocation per leg

Common: `AI_MEMORY_NO_CONFIG=1` skips the host `config.toml` (so `tier` falls back to
the compiled default `semantic` → MiniLM-384, and no stray `db`/`embeddings` leak in).

**Leg 1 — API mTLS** (`ServeArgs`: `--tls-cert` src/daemon_runtime.rs:757,
`--tls-key` :760, `--mtls-allowlist` :771; wired at :5150/:5158/:5163):
```bash
# AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1 is redundant since v0.9.0 (#1751):
# store-path attestation is REQUIRED by default (=0 opts out). Set explicitly here
# only to pin the posture; the launch is byte-identical to omitting it.
AI_MEMORY_NO_CONFIG=1 AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1 \
ai-memory serve --host 0.0.0.0 --port 9077 --store-url "$PG_URL" \
  --tls-cert out/server.crt --tls-key out/server.key \
  --mtls-allowlist out/allowlist.txt
# client: curl --cert out/client-good.crt --key out/client-good.key https://<host>:9077/api/v1/health
```

**Leg 2 — federation/quorum mTLS** (`--quorum-writes` :786, `--quorum-peers` :791,
`--quorum-client-cert` :804, `--quorum-client-key` :807, `--quorum-ca-cert` :815):
```bash
# on peerA (symmetric on peerB, swapping certs + peer host):
AI_MEMORY_NO_CONFIG=1 ai-memory serve --host 0.0.0.0 --port 9077 --store-url "$PG_URL" \
  --tls-cert out/peerA.crt --tls-key out/peerA.key --mtls-allowlist out/peerA.allowlist \
  --quorum-writes 2 --quorum-peers https://<peerB>:9077 \
  --quorum-client-cert out/peerA.crt --quorum-client-key out/peerA.key \
  --quorum-ca-cert out/ca.crt --quorum-timeout-ms 8000
```

**Leg 3 — daemon→Postgres verify-full** (sqlx `PgConnectOptions`, src/store/postgres.rs:829;
sslmode/sslrootcert honoured from the URL query):
```bash
PG_URL="postgres://aimemory:PW@<pg-host>:5432/aimemory?sslmode=verify-full&sslrootcert=/etc/ai-memory/ca.crt"
# NB: --db and --store-url are MUTUALLY EXCLUSIVE; with a config.toml that sets `db`,
# you MUST run under AI_MEMORY_NO_CONFIG=1 (or remove `db`) or serve refuses to start.
```
Postgres server side (`postgresql.conf`): `ssl=on`, `ssl_cert_file=pg-server.crt`,
`ssl_key_file=pg-server.key` (mode 0600, owned by postgres); `pg_hba.conf` `hostssl`
rows only so plaintext is refused. The pg-server cert SAN MUST equal the host used in
`PG_URL` or verify-full fails the hostname check.

## Attestation keypair-gen + binding

```bash
ai-memory identity generate --agent-id ai:alice --key-dir /etc/ai-memory/keys
PUB=$(ai-memory identity export-pub --agent-id ai:alice --key-dir /etc/ai-memory/keys)
# sqlite store: bind via CLI (agent MUST be registered first; agent-type must be a
# curated value or ai:<name> — 'nhi' is REJECTED):
ai-memory agents register --agent-id ai:alice --agent-type system --db "$DB"
ai-memory agents bind-key --agent-id ai:alice --pubkey "$PUB" --db "$DB"
# postgres store: bind over the admin-gated HTTP route (the CLI bind-key speaks sqlite only):
#   POST /api/v1/agents/ai:alice/pubkey   (routes.rs:18 AGENTS_ID_PUBKEY, #1539 admin-gated)
# sign a write (drift-proof — uses the crate's own canonical CBOR):
SIG=$(target/release/examples/attest_sign --agent-id ai:alice --namespace ns \
  --title T --kind observation --created-at "$(date -u +%Y-%m-%dT%H:%M:%S+00:00)" \
  --content 'body' --priv-file /etc/ai-memory/keys/ai:alice.priv)
# POST it: body {title,content,namespace,tier,signature:$SIG,created_at:<same>} + header X-Agent-Id: ai:alice
```
`build the signer once`: `cargo build --release --example attest_sign`.
