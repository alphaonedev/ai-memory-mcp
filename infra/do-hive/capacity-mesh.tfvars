# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# =============================================================================
# #2921 cross-host federation capacity rung -- 5 real memory nodes.
# =============================================================================
#
# The v1.0.0 enterprise-federation certification's largest unmeasured caveat is
# that the 500-1000 agent / <=50-peer envelope is ARCHITECTED, not MEASURED:
# the largest real-mesh-measured federation was TWO nodes (the Track D
# `memory_count=2` round in README-measurement.md). This var-file raises that
# to FIVE cross-host nodes without changing a single line of the provisioning
# code -- `main.tf`'s `memory_count` already accepts 1..8, its firewall already
# opens `:9077` between memory nodes when `memory_count > 1`, and `federate.sh`
# already loops over `NODE_COUNT` to build a full mesh with per-node peer lists
# and N*(N-1) public-key cross-enrollment. Nothing here is new machinery; this
# file is the parameter set that exercises the machinery that already exists.
#
# Companion single-host evidence (N = 2..50 on one box, Docker bridge):
# `infra/bench-mesh/` + `docs/bench/capacity-envelope-2921.md`. This lane is
# the CROSS-HOST control for that lane: same corpus, same measurements, real
# NICs and real inter-host latency, at one point on the curve.
#
# -----------------------------------------------------------------------------
# MONEY GATE -- UNCHANGED, AND NOT WEAKENED BY THIS FILE
# -----------------------------------------------------------------------------
# `spawn.sh` refuses `terraform apply` unless the OPERATOR sets
# `AI_MEMORY_OPERATOR_DO_SPEND_APPROVED=1`. Its header and
# `README-measurement.md`'s run recipe both state, in terms, that **AI NHI
# agents MUST NOT set that variable -- only the human operator does**. That
# prohibition is a control on WHO may spend, not a hint about how; an agent
# that set it because it had been told spend was approved would be defeating
# the exact control that exists to make such a claim insufficient. So this
# file was authored, and the run recipe below was written, WITHOUT the lane
# ever being applied. See `docs/bench/capacity-envelope-2921.md` section
# "Cross-host leg: prepared, not executed".
#
# Operator run recipe (every command already exists and is unmodified):
#
#   source <operator DO token vault>                 # exports DIGITALOCEAN_TOKEN
#   export AI_MEMORY_OPERATOR_DO_SPEND_APPROVED=1    # operator only
#   export TF_VAR_ssh_pubkey_fingerprint=<operator key fingerprint>
#   cargo build --release --features sal,sal-postgres
#   cargo build --release --example attest_sign
#   cd infra/do-hive
#   ./spawn.sh apply -var-file=capacity-mesh.tfvars  # MONEY-GATED, operator only
#   terraform output -json memory_nodes | jq -r '.[].public_ip' | while read -r ip; do
#     scp ../../target/release/ai-memory "root@$ip:/opt/ai-memory/bin/ai-memory"
#   done
#   ./federate.sh                                    # wire + verify the 5-node mesh
#   ./teardown.sh                                    # stop the meter
#
# Cost (2026 DO pricing; confirm against `./spawn.sh cost` at spawn time):
# 5 x s-2vcpu-4gb at ~$0.036/hr = ~$0.18/hr, no inference, no load-gen
# droplets. A one-hour rung is well inside the ~$2 smoke-test budget the
# do-hive header sets. Billing is per second and stops on destroy.

# Five real federated memory nodes. `main.tf` validates 1 <= memory_count <= 8;
# 5 is the largest rung that stays inside the money-gated hive's own cap while
# being a materially larger mesh than the 2-node Track D round.
memory_count = 5

# W = ceil((N+1)/2) = 3 for N=5, straight off the sizing table in
# docs/federation.md "Multi-peer scaling guidance" -- the configuration the
# documentation PRESCRIBES at this mesh size, not an artificially cheap one.
# `main.tf` independently validates quorum_writes <= memory_count.
quorum_writes = 3

# No load-generator droplets: this rung measures the MESH, and the load is
# offered on-node so it crosses the same authenticated peer channel the
# assertions run over. (The #2438 measurement lane's 5 loadgen droplets answer
# a different question -- one substrate's concurrency knee.)
agent_count = 0

# Same size as the Track D cert round so the two cross-host rounds are
# comparable, and above the 2 GB floor where a node building AGE + pgvector
# from source under load would be measuring swap rather than the substrate.
memory_droplet_size = "s-2vcpu-4gb"
