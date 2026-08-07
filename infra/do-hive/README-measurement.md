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
