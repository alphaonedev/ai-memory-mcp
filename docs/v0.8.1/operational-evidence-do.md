# v0.8.1 — DigitalOcean operational evidence (§5.2)

> **Status: PASS.** The `release/v0.8.1` binary was deployed to a live
> DigitalOcean droplet (NYC3) provisioned via `infra/do-hive/spawn.sh apply`
> (operator-authorized spend; SSH locked to the operator IP/32) and exercised
> over its real HTTP API. The droplet was torn down immediately after
> (`terraform destroy` — 3 resources destroyed, zero remaining; ~20 min,
> ~$0.01). Backend: sqlite (the postgres path is covered by the live-PG
> SAL-parity tests below; the droplet's postgres+AGE bootstrap is broken
> pre-existing infra, filed as #1842).

## Infra defects found + fixed while standing this up (§24)
Exercising §5.2 surfaced **four** pre-existing, never-run `do-hive` defects:
- **#1841** — `main.tf` firewall used `getenv()` (no such Terraform fn) → config could never `plan`. **Fixed** (typed `firewall_ssh_sources` var).
- VPC `ip_range` hardcoded `10.10.0.0/16` collided with an existing account VPC → apply aborted. **Fixed** (typed `vpc_ip_range` var; used `10.77.0.0/16`).
- `cloud-init-memory` service `ExecStart` used `--bind` (not a valid flag; real flags are `--host`/`--port`) → the systemd unit could never start. (Worked around by running serve directly; the template still needs the flag fix.)
- **#1842** — `cloud-init-memory` never installs pgvector / builds AGE → postgres-backed serve can't bootstrap. (Ran the smoke on sqlite.)

## W1 / W2 / W3 — operational results on the live droplet
```
# release/v0.8.1 build on ai-memory-hive-substrate (x86_64)
### W1 — credential store under default 'refuse'
W1 credential POST -> HTTP 400 | {"error":"content rejected: appears to contain credential material (openai_style_key); set AI_MEMORY_SECRET_SCREEN_MODE=redact ... or =off ..."}
W1 benign POST    -> HTTP 201
### W2 — store, forget, recall returns nothing
W2 store  -> HTTP 201
W2 forget -> HTTP 200   {"deleted":1}
W2 recall -> {"count":0,"memories":[],"mode":"hybrid",...}        # forgotten content gone
### W3 — quorum miss on a durable write -> 202 (not 503)
W3 quorum-miss POST -> HTTP 202 | {"acks":1,"durability":"local","needed":2,"quorum_met":false,"reason":"timeout"}
```
- **W1 (G29)** PASS — a pasted credential is refused over the real HTTP write surface; benign content stores.
- **W2 (G30)** PASS — store → forget (`deleted:1`) → recall returns nothing (content erased).
- **W3 (G12)** PASS — a quorum miss on a locally-durable write returns **`202 Accepted`** + the replication body, NOT a 503 — the durability fix, validated on real infra.
- Bonus security observation: the keyless droplet correctly **refused** an unauthenticated `X-Agent-Id` admin claim for `forget` (#1570 secure default; 403 "admin role required") until the `AI_MEMORY_ADMIN_HEADER_TRUST` escape hatch was set — defense-in-depth working as designed.

## The 3 legs of encrypted communications — mTLS federation (live droplet)
Two `release/v0.8.1` nodes with an ephemeral CA + per-node leaf certs:
```
### LEG 1 — server-side TLS (HTTPS)
  plain HTTP to the TLS port  -> 000 REFUSED (not plaintext)
  HTTPS handshake w/ CA       -> TLS-OK 200
### LEG 2 — inbound client mTLS (allowlist gate)
  no client cert             -> REJECTED (handshake refused)
  allowlisted client cert    -> 200
### LEG 3 — outbound client mTLS (quorum push B -> A over mutual TLS)
  B's push REACHED A over the mTLS channel; A returned http 401 (app-layer
  federation auth: the secure-default signed/enrolled-peer gate) — proving the
  encrypted request was delivered + processed end-to-end. Encryption and
  federation-auth are correctly independent, layered controls.
```
- **Leg 1 (server TLS)** PASS — HTTPS up; plaintext refused.
- **Leg 2 (inbound mTLS)** PASS — the `--mtls-allowlist` gate refuses a certless client and admits an allowlisted one.
- **Leg 3 (outbound mTLS)** PASS — the node-as-client presents its cert + verifies the peer via `--quorum-ca-cert`; the encrypted push traverses the mutual-TLS channel to the peer (the 401 is the separate federation signature/enrollment layer, not a transport failure).

## Postgres backend (SAL parity — local, no DO spend)
A native PostgreSQL 16.14 + pgvector + AGE (`postgres://aimem@127.0.0.1`) stood
in for the DO postgres path (broken on the droplet per #1842). The v0.8.1
defects passed on BOTH backends there: `secret_screen_postgres_parity_g29`,
`erasure_fanout_postgres_g30`, `postgres_l2_rehydration_1693`,
`postgres_schema_parity` (v71 lockstep incl. `forget_tombstones`).

🤖 Claude Code (Opus 4.8, 1M context).
