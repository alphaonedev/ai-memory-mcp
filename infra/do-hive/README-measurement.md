# #2438 capacity-measurement cluster + USL projection

Measurement scaffolding for the v1.0.0 certification-scope campaign
([#2438](https://github.com/alphaonedev/ai-memory-mcp/issues/2438) /
[#2437](https://github.com/alphaonedev/ai-memory-mcp/issues/2437)). It closes the
"14-cell ops/s grid has no producer" gap by MEASURING one substrate module's
throughput-vs-concurrency curve on a small, cost-economical 5-droplet Digital
Ocean cluster, then fitting the Universal Scalability Law to PROJECT (labelled
ESTIMATED-not-MEASURED) toward a 500-agent block.

This is the ACCEPTED design in `.local-runs/measurement-design-2438.md`, built as
an ADDITIVE extension of the existing `infra/do-hive` provisioning + the
`infra/pillar4-envelope/measure-envelope.sh` op-mix instrument. The default
IronClaw-hive path is byte-identical; the measurement path is a toggle.

> **Also in this file:** the [Track D federated multi-node round](#track-d----federated-multi-node-cert-round-memory_count2)
> for the v1.0.0 enterprise-certification campaign. Same money gate, same
> teardown, different toggle (`-var memory_count=2`).

## What this is NOT (honest scope)

Read this first. It bounds every number the campaign can honestly publish.

- It is **NOT** a 1000-agent single-federated-system certification. A 500-agent
  block served by a federated mesh larger than the documented **~50-peer ceiling**
  (`docs/enterprise-deployment.md` §8.8) requires a cross-mesh membership /
  placement layer that **does not exist at v1.0.0** (#2438 path 1). Any such
  number is architecturally UNPROVEN, not merely unmeasured.
- The measured unit is **substrate capacity under a synthetic op mix** (tight
  loop, zero think-time, fixed ~64-byte payloads). It is an UPPER bound on what a
  real LLM-paced agent needs, NOT a real-agent number.
- Numbers are **host-relative** (DO shared-CPU droplets have noisy-neighbour
  variance and are not a production T5/T6 box). The CURVE SHAPE and RELATIVE
  scaling law transfer more reliably than the absolute ops/s, which do not. Every
  published number MUST cite the host + corpus scale.
- The USL projection to 500/1000 is **ESTIMATED**, with a confidence band that
  widens with distance from the max measured concurrency. If the ramp never
  reaches the knee, the projection degrades to a **lower bound**, never a
  fabricated point estimate.

## The unit + the composition rule (what #2438 requires)

- **Unit of scale:** one agent = one concurrent client identity issuing the
  canonical `store -> link(prev->cur) -> recall` op mix (the exact
  `measure-envelope.sh` worker loop) over the HTTP surface (`:9077`).
- **500-agent block:** 500 such agents concurrently offered to ONE substrate
  module (one `ai-memory serve` over one postgres+AGE backbone).
- **Composition rule (v1.0.0):** cluster capacity for A agents = M independent
  substrate modules, `M = ceil(A / A_module*)`, where `A_module*` is the MEASURED
  USL knee `N*` held at the p95 budget on the cited host. Modules federate as
  static-list peers; the mesh is bounded at **<= 50 peers**. A block or cluster
  needing **> 50 modules** needs the placement architecture that does not exist at
  v1.0.0 and is therefore NOT certifiable by composition of the measured unit.

## Run recipe (operator-driven; the orchestrator does not spend)

Spend is money-gated by the UNCHANGED `spawn.sh` — it refuses `terraform apply`
unless the OPERATOR sets `AI_MEMORY_OPERATOR_DO_SPEND_APPROVED=1`. AI agents MUST
NOT set that var. The scaffolding here is safe to merge and safe to dry-run; only
the operator triggers the paid steps.

```bash
# 0. Operator sources the DO token vault + approves spend (operator only).
source <operator DO token vault>          # exports DIGITALOCEAN_TOKEN
export AI_MEMORY_OPERATOR_DO_SPEND_APPROVED=1
export TF_VAR_ssh_pubkey_fingerprint=<operator key fingerprint>

# 1. Provision: 5 smallest load-gen droplets + one bumped substrate droplet.
#    ai_memory_image_url MUST be a --features sal-postgres build (see the
#    cloud-init-memory NOTE); scp a local sal-postgres binary over the
#    provisioned one for an ad-hoc run.
cd infra/do-hive
./spawn.sh apply -var-file=measurement.tfvars    # MONEY-GATED, operator only

# 2. Derive the IPs from the terraform outputs.
terraform output -json > outs.json
export SUBSTRATE_IP=$(jq -r .memory_private_ip.value outs.json)
export LOADGEN_IPS=$(jq -r '.agent_ips.value | join(" ")' outs.json)

# 3. Drive the concurrency ramp at droplet-counts N in {1,2,3,5} x the internal
#    per-droplet ramp, collecting per-op ops/s at each offered-concurrency level.
#    Emits a machine-readable results JSON.
cd ../pillar4-envelope
SEED=1 CORPUS_SCALE=10000 BACKEND=postgres SUBSTRATE_HOST=s-2vcpu-4gb \
  ./measure-capacity-ramp.sh          # writes .local-runs/capacity-<ts>.json

# 4. Fit the USL and project to 500 (and 1000). Every projected number is
#    labelled ESTIMATED-not-MEASURED; interpolation inside the ramp is MEASURED.
./usl-fit.py .local-runs/capacity-<ts>.json --target 500 --budget-ms 250

# 5. Stop the meter. Idempotent; per-second billing stops on droplet destroy.
cd ../do-hive
./teardown.sh
```

Cost (2026 DO pricing, confirm at spawn): substrate `s-2vcpu-4gb` ~$0.036/hr + 5x
`s-1vcpu-1gb` ~$0.012/hr = ~$0.096/hr, NO inference (load-gen does zero LLM).
Budget the campaign at ~$2, inside the do-hive header's own smoke-test budget.

## The pieces

| file | role |
|---|---|
| `cloud-init-loadgen.yaml.tpl` | load-generator droplet bootstrap (curl + python3 only; no IronClaw, no LLM). Drops the `measure-envelope.sh` op-mix worker + a per-droplet runner at `/opt/loadgen/`, plus a DISABLED systemd unit. Selected by `main.tf` when `agent_workload=="loadgen"`. |
| `main.tf` (`agent_workload` var) | additive toggle; default `ironclaw` keeps the hive path byte-identical. |
| `measurement.tfvars` | 5x `s-1vcpu-1gb` load-gen + one `s-2vcpu-4gb` substrate, `agent_workload=loadgen`. |
| `../pillar4-envelope/measure-capacity-ramp.sh` | orchestrator-side ramp driver. SSHes into the provisioned droplets (never spawns them), runs the per-droplet op-mix at each offered-concurrency level, aggregates with the SAME reducer as `measure-envelope.sh`, emits results JSON. `--self-test` validates the JSON contract without droplets. |
| `../pillar4-envelope/usl-fit.py` | numpy-free USL least-squares fit; reports (lambda, sigma, kappa), knee `N* = sqrt((1-sigma)/kappa)`, and the ESTIMATED T(500) projection with a leave-one-out confidence band. `--self-test` recovers a known ground truth. |

## Safety properties (why this is safe to merge)

- The money-gate, VPC, `:9077` east-west firewall, and idempotent teardown in
  `infra/do-hive` are UNTOUCHED. The only edit to an existing resource is the
  `templatefile` path ternary; the var map is unchanged, so the default hive path
  is byte-identical.
- `measure-capacity-ramp.sh` NEVER calls terraform and NEVER spawns droplets; it
  only SSHes into an already-provisioned cluster and refuses (exit non-zero) with
  no `SUBSTRATE_IP` / `LOADGEN_IPS`.
- The measurement writes only short-tier rows in a throwaway `envelope` namespace
  on a throwaway cluster that teardown destroys. It MUST NEVER run against a
  substrate holding real memories (data-integrity North Star: the ramp writes are
  disposable and the DB is discarded).
- The load-gen cloud-init is ASCII-only (the #1880 `check-cloud-init-ascii.sh`
  gate) and its embedded bash uses only unbraced shell vars so Terraform's
  `${...}` / `%{...}` interpolation never collides with it.

---

# Track D -- federated multi-node cert round (`memory_count=2`)

Track D of the v1.0.0 enterprise-certification campaign
(`docs/v1.0.0/test-campaign-2026-08-08-enterprise-cert/PLAN.md` Track D + §3)
requires **REAL federated multi-node ai-memory across droplets**: an enrolled
quorum, mutual TLS on the peer channel, per-write content signatures, and a
W-of-N write. The local harnesses
(`crypto/test-federation-mtls.sh`, `crypto/test-fed-write-sig-attestation.sh`)
prove the *config*, but both their peers share one loopback interface and one
process table, so they cannot prove cross-host reachability. This is the
re-host.

`main.tf` grows one variable, `memory_count` (default `1`). At the default the
rendered `cloud-init-memory.yaml.tpl` user_data is **byte-identical** to the
pre-Track-D template (verified by rendering both and `cmp`), so the existing
IronClaw hive and the #2438 measurement cluster are untouched.

## What gets provisioned at `memory_count=2`

| piece | detail |
|---|---|
| droplets | `ai-memory-hive-memory-1` + `-2` on the existing VPC, same size/image as before |
| firewall | `:9077` east-west additionally opened **between memory nodes** (only when `memory_count > 1`); SSH + outbound rules unchanged |
| serve | a systemd **drop-in** (`ai-memory.service.d/10-federation.conf`) overrides only `ExecStart`; the base unit stays byte-identical, so the postgres/AGE/pgvector half cannot drift between the two topologies |
| mTLS | each node presents its own leaf as BOTH server and outbound quorum client cert; `--mtls-allowlist` pins every other node + itself and nothing else (`crypto/gen-certs.sh` `HIVE_NODE_IPS` mode). No operator/bastion cert is minted -- an unused trust anchor is a liability, and the assertions run on-node with material the mesh already trusts |
| quorum | `--quorum-writes 2 --quorum-peers https://<peer-private-ip>:9077 --quorum-ca-cert ... --quorum-timeout-ms 8000` |
| federation identity | `ai:hive-memory-N`, Ed25519 keypair **generated on the droplet**; only the `.pub` ever leaves |
| `AI_MEMORY_FED_*` | **all left UNSET on purpose.** At v1.0.0 write-sig / signal-sig / transition-sig / checkpoint-sig / nonce / peer-enrollment / policy-current are fail-closed by compiled default. Setting them to `1` would prove "the flag works", not "the shipped default is secure" |
| api key | minted **on** each droplet (`openssl rand -hex 32` -> `/etc/ai-memory/api-key`, mode 0600). The daemon correctly refuses a non-loopback bind without one (`crypto/KNOWN-DO-STAGING.md` §3) |

## Why there is a second command (`federate.sh`)

Two constraints make peer wiring necessarily post-apply, and both are
load-bearing rather than convenience:

1. **Terraform cannot express it.** A DO droplet's private IPv4 is allocated at
   create time and `digitalocean_droplet` has no input for it, so node 1's
   `user_data` cannot reference node 2's address. With `count`, terraform models
   the whole resource as ONE graph node, so even `memory[1 - count.index]` is a
   hard `Cycle: digitalocean_droplet.memory` at plan time -- a resource cannot
   reference itself.
2. **Secrets must stay out of terraform state.** Anything rendered into
   `user_data` lives verbatim in `terraform.tfstate` -- which `spawn.sh` COPIES
   into `.local-runs/do-hive-runs/<ts>/` on every apply -- and is readable from
   the droplet's own metadata service. So the CA + leaf private keys are minted
   on the operator host and pushed over SSH instead.

**Rejected alternative:** generate on droplet 1 and distribute to the others.
There is no authenticated channel between two fresh droplets *before* the mTLS
material exists (that material *is* the channel), so the bootstrap would be
trust-on-first-use over plaintext -- and a federation-encryption certification
cannot rest on a plaintext, unauthenticated key exchange.

**Honest cost:** `terraform apply` alone does not yield a running mesh. It
yields two nodes parked in a **fail-closed wait** (the drop-in's
`EnvironmentFile` has no leading `-`, so systemd refuses to start `serve`
until the peer list lands), and one operator command completes them. That step
is the one `crypto/KNOWN-DO-STAGING.md` §1 already prescribes.

## Run recipe

```bash
# 0. Operator vault + spend approval (operator only; AI agents MUST NOT set this).
source <operator DO token vault>                  # exports DIGITALOCEAN_TOKEN
export AI_MEMORY_OPERATOR_DO_SPEND_APPROVED=1
export TF_VAR_ssh_pubkey_fingerprint=<operator key fingerprint>

# 1. Build the artifacts federate.sh needs on THIS host.
cargo build --release --features sal,sal-postgres
cargo build --release --example attest_sign

# 2. Provision 2 substrate nodes. MONEY-GATED; ~$0.048/hr for the pair.
cd infra/do-hive
./spawn.sh apply -var memory_count=2 -var agent_count=0

# 3. Put a #1882-fixed sal-postgres binary on each node (the cloud-init NOTE:
#    serve only starts once such a binary is present).
terraform output -json memory_nodes | jq -r '.[].public_ip' | while read -r ip; do
  scp target/release/ai-memory "root@$ip:/opt/ai-memory/bin/ai-memory"
done

# 4. Wire the mesh + run the Track D assertions. NEVER calls terraform-apply,
#    never spawns a droplet; refuses if the outputs do not describe >= 2 nodes.
./federate.sh                # == ./federate.sh wire && ./federate.sh verify

# 5. Stop the meter. UNCHANGED - idempotent, per-second billing stops on destroy.
./teardown.sh
```

`spawn.sh` and `teardown.sh` are untouched: the money gate
(`AI_MEMORY_OPERATOR_DO_SPEND_APPROVED=1`), the audit dump, and the idempotent
destroy behave exactly as before.

## What to verify post-boot

`./federate.sh verify` asserts each of these and exits non-zero if any FAILs
(same PASS/FAIL shape as the `crypto/test-*.sh` legs).

**Every assertion runs ON a droplet over SSH, never from the orchestrator
host.** The peer URLs are PRIVATE VPC addresses and the `:9077` rule admits
only hive droplet ids, so a curl from outside could not reach them even if the
address routed; running on-node also keeps the client-cert set to material the
mesh already trusts.

| assertion | expected |
|---|---|
| each node `/api/v1/health` over mTLS (its own peer cert, via loopback) | `200` |
| each node with **no** client cert | connection refused at the rustls allowlist (mTLS is mandatory) |
| **cross-host**: node 1 -> node 2 at `https://<node-2 private ip>:9077/api/v1/health` with node 1's peer cert | `200` -- the assertion the local 2-daemon legs structurally cannot make |
| a `W=2` quorum write admitted at node 1 | `201 quorum_met` (or `202` locally-durable if the ack lands late -- both prove the mutually authenticated channel carried it) |
| that row read back from **node 2** | present -- the write actually replicated |
| a **signed** write authored `ai:hive-author` on node 1, read at node 2 | `metadata.attest_level == "agent_attested"` -- proves EMIT + cross-peer author enrollment + the v1.0.0 default-on write-sig flip together |

Manual spot checks if a leg goes red:

```bash
IP1=$(terraform output -json memory_nodes | jq -r '.[0].public_ip')
ssh root@$IP1 'systemctl status ai-memory-fed-bootstrap --no-pager'
ssh root@$IP1 'tail -40 /var/log/ai-memory-federation.log'   # per-stage trace
ssh root@$IP1 'journalctl -u ai-memory -n 60 --no-pager'
ssh root@$IP1 'cat /etc/ai-memory/api-key'                   # per-node shared key
ssh root@$IP1 'ls /etc/ai-memory/keys'                       # own .priv/.pub + peer .pub
```

The bootstrap is a resumable state machine; after fixing a cause, re-run it
with `systemctl restart ai-memory-fed-bootstrap`. It never deletes or rewrites
durable memory text.

## Safety properties of the Track D lane

- **`memory_count=1` is byte-identical.** Every federation stanza sits behind a
  `%{ if federation_enabled }` template directive; rendering the new template at
  `memory_count=1` and `cmp`-ing it against the pre-Track-D render is clean.
  `crypto/gen-certs.sh` is likewise additive -- with `HIVE_NODE_IPS` unset it
  emits exactly the legacy localhost/peerA/peerB material.
- **No secrets in terraform state.** Terraform carries only `node_index`,
  `node_count`, `fed_identity` and `quorum_writes`. CA + leaf private keys move
  operator-host -> droplet over SSH; the nodes' Ed25519 signing keys never move
  at all.
- **Residual risk this lane ACCEPTS (disclosed, not closed): the SSH push is
  trust-on-first-use.** The channel that carries the CA private key and each
  node's leaf `node.key` is `federate.sh`'s SSH, which defaults to
  `StrictHostKeyChecking=accept-new`. A first-contact MITM on the
  operator -> droplet path would obtain that material. The residual is accepted
  because the hive is ephemeral, money-gated, and operator -> own-droplet. An
  operator who does not want to accept it can pre-seed `known_hosts` from the
  DO console host keys, or export
  `SSH_OPTS='-o StrictHostKeyChecking=yes -o ConnectTimeout=15'` with the host
  key pinned. Stated here because disclosing only the exposure this design
  CLOSES (terraform state / droplet metadata) while omitting the one it DEPENDS
  ON would be exactly the asymmetry the campaign's truthfulness discipline
  exists to prevent.
- **Fail-closed, not silently-degraded.** A node with no peer list refuses to
  start rather than running as a one-node "mesh" that satisfies nothing while
  reporting healthy. `fed-bootstrap.sh` additionally refuses a non-`https` peer
  URL locally, mirroring the daemon's own #2477 boot refusal, so the cause is
  named in the log instead of surfacing as an opaque unit failure.
- **Cross-enrollment moves public material only.** Peer `.pub` files and the
  author `.pub` -- never a `.priv` -- exactly the discipline
  `infra/lan-parity-test/provision-peer-keys.sh` follows for the docker mesh
  (#1803).
- **ASCII-clean cloud-init.** The template stays pure ASCII (#1880 gate) and all
  braced shell expansions are `$$`-escaped so terraform interpolation never
  collides with bash or with curl's `%{http_code}`.
- **`federate.sh` spends nothing.** It reads `terraform output` and SSHes into
  an already-provisioned cluster; it never invokes `terraform apply` and refuses
  with no side effects when fewer than 2 memory nodes exist.
- **`memory_count` is capped at 8** so a mistyped value cannot mint a
  50-droplet bill; `docs/enterprise-deployment.md` §8.8's ~50-peer federation
  ceiling is far above anything this money-gated test hive should provision.
# Phase A (V&V swarm, agents off-DO)

Phase A provisions only the certified data tier. GLM-5.3-Flash calls and the
swarm driver stay on f2; the public API leg is TLS plus fingerprint-pinned mTLS.
The daemon also requires its per-node API key. `AI_MEMORY_ADMIN_HEADER_TRUST`
is never enabled: the unit loads `AI_MEMORY_ADMIN_AGENT_IDS=ai:hive-loadgen-f2`
from `/etc/ai-memory/fed/runtime.env`, and the loadgen must present both its
enrolled certificate and `X-API-Key`. The serve flags are always
`--tls-cert /etc/ai-memory/fed/node.crt --tls-key ... --mtls-allowlist ...`;
only `--quorum-*` flags are conditional on `memory_count >= 2`.

```bash
export TF_VAR_ssh_pubkey_fingerprint=b5:bf:33:9d:6f:a7:22:60:87:49:36:0b:7a:fe:ba:e9
infra/do-hive/spawn.sh plan -var memory_count=1 -var agent_count=0 \
  -var memory_droplet_size=c-8 -var 'loadgen_sources=["108.45.154.178/32"]'

# Operator only: explicitly approve spend, then use the exact apply command
AI_MEMORY_OPERATOR_DO_SPEND_APPROVED=1 infra/do-hive/spawn.sh apply \
  -var memory_count=1 -var agent_count=0 -var memory_droplet_size=c-8 \
  -var 'loadgen_sources=["108.45.154.178/32"]'

scp target/release/ai-memory root@"$(terraform -chdir=infra/do-hive output -raw memory_public_ip)":/opt/ai-memory/bin/ai-memory
infra/do-hive/federate.sh wire
infra/do-hive/federate.sh loadgen
infra/do-hive/federate.sh verify

export SWARM_BASE_URL="https://$(terraform -chdir=infra/do-hive output -raw memory_public_ip):9077"
export SWARM_CLIENT_CERT="$PWD/.local-runs/do-hive-runs/<UTC>/loadgen/client.crt"
export SWARM_CLIENT_KEY="$PWD/.local-runs/do-hive-runs/<UTC>/loadgen/client.key"
export SWARM_CA_CERT="$PWD/.local-runs/do-hive-runs/<UTC>/loadgen/ca.crt"
export SWARM_API_KEY="$(ssh root@"$(terraform -chdir=infra/do-hive output -raw memory_public_ip)" cat /etc/ai-memory/api-key)"
PYTHONPATH=sdk/python python -m swarm

infra/do-hive/teardown.sh
```

The substrate is PostgreSQL 18.6, AGE 1.8.0, and pgvector 0.8.6. PgBouncer
listens only on `127.0.0.1:6432`, uses transaction pooling, and admits 2000
clients; the daemon points its store URL there so Phase A and Phase B share the
same baseline.
