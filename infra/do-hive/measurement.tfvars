# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# =============================================================================
# #2438 capacity-measurement cluster (design: .local-runs/measurement-design-2438.md).
# =============================================================================
#
# 5 smallest load-generator droplets + one bumped substrate droplet. Applied via
# the SAME money-gated wrapper as the E1 hive -- spend is NOT weakened:
#
#   export AI_MEMORY_OPERATOR_DO_SPEND_APPROVED=1     # operator only
#   export DIGITALOCEAN_TOKEN=...                     # operator vault
#   export TF_VAR_ssh_pubkey_fingerprint=...          # operator key
#   infra/do-hive/spawn.sh apply -var-file=measurement.tfvars   # operator only
#   infra/pillar4-envelope/measure-capacity-ramp.sh             # drive the ramp
#   infra/pillar4-envelope/usl-fit.py <results.json>            # fit + project
#   infra/do-hive/teardown.sh                                   # stop the meter
#
# Cost (2026 DO pricing, confirm at spawn): substrate s-2vcpu-4gb ~$0.036/hr +
# 5 x s-1vcpu-1gb ~$0.012/hr = ~$0.096/hr. NO inference (load-gen does zero LLM),
# which is the big saving vs the IronClaw hive. Budget the campaign at ~$2.
# Per-second billing; teardown.sh stops accrual immediately.

# 5 load generators, each running the curl+python3 op mix (no IronClaw, no XAI).
agent_count    = 5
agent_workload = "loadgen"

# Agents only run a curl loop -- the smallest droplet is enough.
agent_droplet_size = "s-1vcpu-1gb"

# Substrate bumped one notch above the hive default so the MEASURED knee is a
# real substrate knee, not a swap-thrash artifact on a 2GB box building AGE +
# pgvector from source and serving pg16 + AGE + pgvector under load.
memory_droplet_size = "s-2vcpu-4gb"

# NOTE: the substrate binary MUST be a `--features sal-postgres` build (the
# cloud-init-memory template flags this). Point ai_memory_image_url at a
# sal-postgres tarball or scp a local build over the provisioned one, per the
# cloud-init NOTE. ssh_pubkey_fingerprint is supplied via TF_VAR (operator key).
