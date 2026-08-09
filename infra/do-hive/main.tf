// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// =============================================================================
// Track E1 — Digital Ocean CPU agent hive (issue #833).
// =============================================================================
//
// Status: MONEY-GATED. This Terraform manifest is IaC-only — no `terraform
// apply` is performed by AI agents. The operator triggers spend explicitly
// (see `infra/do-hive/spawn.sh` for the wrapped invocation).
//
// Cost estimate (NYC3, on-demand droplets, 2026 pricing as published at
// https://www.digitalocean.com/pricing/droplets):
//
//   resource            qty  price/hr   total/hr   total/24h   total/month
//   -------------------------------------------------------------------------
//   ai-memory droplet   1    $0.024     $0.024     $0.58       $17.41
//     (s-1vcpu-2gb, postgres + AGE + ai-memory daemon)
//   agent droplet       N    $0.012     $0.012N    $0.29N      $8.70N
//     (s-1vcpu-1gb, IronClaw runner)
//   vpc + firewall      —    $0         $0         $0          $0
//   inference (xAI Grok 4.3 API)            offload — billed per-token to operator's xAI account
//
// Worked totals (N = number of agent droplets):
//
//   N = 4     → $0.072/hr  → $1.73/24h  → ~$51/month
//   N = 10    → $0.144/hr  → $3.46/24h  → ~$104/month  ← reference "hive"
//   N = 25    → $0.324/hr  → $7.78/24h  → ~$234/month
//   N = 50    → $0.624/hr  → $14.98/24h → ~$449/month
//
// Variable `agent_count` defaults to 10 (the operator-defended reference
// hive size from #833's D1-D5 demo capture brief). Bump for larger
// emergent-behavior runs; the math above scales linearly.
//
// Variable `memory_count` defaults to 1 (the historical single-substrate
// hive). `-var memory_count=2` provisions the v1.0.0 enterprise-cert
// Track-D federated mesh — see `README-measurement.md` §"Track D".
// Each additional memory droplet costs the same $17.41/month as the first.
//
// Smoke-test playbook (~$2 budget):
//   1. operator: `infra/do-hive/spawn.sh apply` (1h smoke, agent_count=4)
//   2. agents come online via cloud-init bootstrap
//   3. capture D1-D5 outputs (cross-agent memory, recursive reflection)
//   4. operator: `infra/do-hive/teardown.sh` (idempotent)
//
// Audit hook: every spawn writes the resolved droplet IDs + IPs +
// SHA256(droplet_user_data) to `.local-runs/do-hive-runs/<ts>/` so a
// post-mortem can reconstruct exactly which agent saw what code.
//
// Money-gate enforcement: `spawn.sh` REQUIRES the env var
// `AI_MEMORY_OPERATOR_DO_SPEND_APPROVED=1` to be set before delegating
// to `terraform apply`. AI NHI agents MUST NOT set this var; only the
// human operator does.
// =============================================================================

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.40"
    }
  }
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------
//
// Token is sourced from the operator's `DIGITALOCEAN_TOKEN` env var. NEVER
// commit a token to this file. The `spawn.sh` wrapper re-exports the var
// from the operator's keychain (1Password / op vault) so the value never
// touches a repo file.

provider "digitalocean" {}

// ---------------------------------------------------------------------------
// Variables
// ---------------------------------------------------------------------------

variable "region" {
  description = "DO region. NYC3 has the lowest sustained-rate cost as of 2026-05."
  type        = string
  default     = "nyc3"
}

variable "agent_count" {
  description = "Number of agent droplets to spawn. Reference hive: 10 (≈$0.144/hr)."
  type        = number
  default     = 10
}

variable "memory_droplet_size" {
  description = "Slug for the shared ai-memory + postgres droplet."
  type        = string
  default     = "s-1vcpu-2gb"
}

// ---------------------------------------------------------------------------
// Track D (v1.0.0 enterprise-cert campaign) — federated multi-node substrate
// ---------------------------------------------------------------------------
//
// `docs/v1.0.0/test-campaign-2026-08-08-enterprise-cert/PLAN.md` Track D needs
// REAL federated multi-node ai-memory across droplets (enrolled quorum, mTLS,
// write-sig, W-of-N) — something the local 2-daemon harnesses
// (`infra/do-hive/crypto/test-federation-mtls.sh`,
// `infra/do-hive/crypto/test-fed-write-sig-attestation.sh`) cannot prove
// because both peers share a loopback interface and one process table.
//
// `memory_count = 1` (default) keeps the historical single-substrate hive:
// the rendered `cloud-init-memory.yaml.tpl` user_data is BYTE-IDENTICAL to
// pre-Track-D (every federation stanza is behind a `%{ if federation_enabled }`
// directive that renders to nothing), and the firewall/agent wiring is
// unchanged.
//
// STATE-MOVE NOTICE (data integrity — read before applying to a LIVE hive):
// adding `count` moves this resource's state address from
// `digitalocean_droplet.memory` to `digitalocean_droplet.memory[0]` AND
// renames the droplet `ai-memory-hive-substrate` -> `ai-memory-hive-memory-1`.
// On a hive whose state predates this commit, run
//
//     terraform state mv 'digitalocean_droplet.memory' 'digitalocean_droplet.memory[0]'
//
// BEFORE the next plan. Without the move terraform destroys + recreates the
// substrate droplet, which destroys its postgres volume and every memory in
// it. The rename alone also forces replacement (`name` is a ForceNew
// attribute on `digitalocean_droplet`), so a LIVE hive that must keep its
// corpus should snapshot / `ai-memory backup` first. The hive is a
// money-gated ephemeral test fleet by design, but the substrate DB is still
// durable text while it exists.

variable "memory_count" {
  description = "Number of ai-memory substrate droplets. 1 (default) = the historical single-substrate hive; the rendered cloud-init is byte-identical to pre-Track-D. >=2 provisions a REAL federated mesh (mutual mTLS, enrolled Ed25519 peers, W-of-N quorum) for Track D of the v1.0.0 enterprise-cert campaign. The cert round uses 2."
  type        = number
  default     = 1

  validation {
    condition     = var.memory_count >= 1 && var.memory_count <= 8
    error_message = "memory_count must be between 1 and 8. docs/enterprise-deployment.md 8.8 documents a ~50-peer federation ceiling; this money-gated test hive caps far below it so a mistyped value cannot mint a 50-droplet bill."
  }
}

variable "quorum_writes" {
  description = "W of the W-of-N federation write quorum on each memory node. Consumed ONLY when memory_count >= 2. Default 2 mirrors the certified local 2-node config (infra/do-hive/crypto/test-federation-mtls.sh: --quorum-writes 2)."
  type        = number
  default     = 2

  validation {
    condition     = var.quorum_writes >= 2
    error_message = "quorum_writes must be >= 2. W=1 requires no peer acknowledgement at all, collapsing the W-of-N durability guarantee to a local-only commit while still reporting quorum_met."
  }
}

variable "agent_droplet_size" {
  description = "Slug for each agent droplet (IronClaw runner)."
  type        = string
  default     = "s-1vcpu-1gb"
}

variable "agent_workload" {
  description = "Which workload the agent droplets run: 'ironclaw' (default; the E1 emergent-behavior hive) or 'loadgen' (#2438 capacity-measurement load generators -- curl+python3 op mix, no IronClaw, no LLM inference). The default keeps the IronClaw hive path byte-identical; measurement.tfvars selects 'loadgen'."
  type        = string
  default     = "ironclaw"

  validation {
    condition     = contains(["ironclaw", "loadgen"], var.agent_workload)
    error_message = "agent_workload must be 'ironclaw' or 'loadgen'."
  }
}

variable "ssh_pubkey_fingerprint" {
  description = "SSH key fingerprint to authorise on every droplet. Operator's key."
  type        = string
}

variable "firewall_ssh_sources" {
  description = "CIDR list allowed to SSH (port 22) to the hive droplets. Set TF_VAR_firewall_ssh_sources to the operator CIDR(s). Defaults open (key-only auth on short-lived smoke-test droplets) — restrict for any non-ephemeral hive."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "vpc_ip_range" {
  description = "Private CIDR for the hive VPC. Must not overlap an existing account VPC. Override via TF_VAR_vpc_ip_range if 10.20.0.0/16 is taken."
  type        = string
  default     = "10.20.0.0/16"
}

variable "db_password" {
  description = "PostgreSQL password for the ai-memory role (substrate-local; the daemon connects over localhost only — postgres is not exposed to the network). Pass via TF_VAR_db_password."
  type        = string
  default     = "aimem-do-substrate"
  sensitive   = true
}

variable "ai_memory_image_url" {
  description = "URL to the pre-built ai-memory release tarball (operator-published)."
  type        = string
  default     = "https://github.com/alphaonedev/ai-memory-mcp/releases/latest/download/ai-memory-x86_64-unknown-linux-gnu.tar.gz"
}

variable "ironclaw_image_url" {
  description = "URL to the IronClaw v1.1.0 runner tarball."
  type        = string
  default     = "https://github.com/nearai/ironclaw/releases/download/ironclaw-v1.1.0/ironclaw-x86_64-unknown-linux-gnu.tar.gz"
}

// ---------------------------------------------------------------------------
// VPC — isolates the hive's east-west traffic from public internet
// ---------------------------------------------------------------------------

resource "digitalocean_vpc" "hive" {
  name   = "ai-memory-hive-${var.region}"
  region = var.region
  // v0.8.1 §5.2 — was hardcoded 10.10.0.0/16, which collides with any
  // pre-existing account VPC on that range (it did: do-1461-vpc-fra1) and
  // aborts the whole apply. Now a variable so each hive picks a free range.
  ip_range = var.vpc_ip_range
}

// ---------------------------------------------------------------------------
// ai-memory droplet(s) (substrate)
// ---------------------------------------------------------------------------
//
// Runs postgres + Apache AGE + the ai-memory autonomous-tier daemon on
// :9077. Bound to the VPC private IP so only hive droplets in the same
// VPC can reach it; no public ingress on :9077.
//
// PEER-IP WIRING — why peer addresses do NOT ride templatefile vars.
// A DO droplet's private IPv4 is allocated by the provider at CREATE time and
// `digitalocean_droplet` has no input for it, so node N's user_data cannot
// reference node M's `ipv4_address_private`: with `count`, terraform models
// the whole resource as one graph node, so any self-reference (even a
// `count.index`-arithmetic one like `memory[1 - count.index]`) is a hard
// `Cycle: digitalocean_droplet.memory` error at plan time — terraform
// resources cannot reference themselves. The peer list is therefore delivered
// POST-CREATE by `federate.sh`, which reads the `memory_nodes` output below
// and writes `/etc/ai-memory/fed/peers.conf` on each node over SSH; the
// on-droplet one-shot `ai-memory-fed-bootstrap.service` blocks until it
// lands. What DOES ride templatefile vars is everything knowable at plan
// time: `node_index`, `node_count`, `fed_identity`, `quorum_writes`.

resource "digitalocean_droplet" "memory" {
  count    = var.memory_count
  image    = "ubuntu-24-04-x64"
  name     = "ai-memory-hive-memory-${count.index + 1}"
  region   = var.region
  size     = var.memory_droplet_size
  vpc_uuid = digitalocean_vpc.hive.id
  ssh_keys = [var.ssh_pubkey_fingerprint]

  // Track D: the federation stanzas in the template are guarded by
  // `%{ if federation_enabled }`, so at memory_count=1 this renders
  // byte-identically to the pre-Track-D template (verified by rendering both
  // and diffing against the parent commit).
  user_data = templatefile("${path.module}/cloud-init-memory.yaml.tpl", {
    ai_memory_image_url = var.ai_memory_image_url
    db_password         = var.db_password
    federation_enabled  = var.memory_count > 1
    node_index          = count.index + 1
    node_count          = var.memory_count
    fed_identity        = "ai:hive-memory-${count.index + 1}"
    quorum_writes       = var.quorum_writes
  })

  lifecycle {
    precondition {
      condition     = var.quorum_writes <= var.memory_count || var.memory_count == 1
      error_message = "quorum_writes must be <= memory_count. A W larger than N can never be satisfied: every federated write would burn the full --quorum-timeout-ms and then return 202 locally-durable, so the mesh would look alive while replicating nothing."
    }
  }

  tags = ["ai-memory-hive", "ai-memory-substrate"]
}

// ---------------------------------------------------------------------------
// Agent droplets — IronClaw runners
// ---------------------------------------------------------------------------

resource "digitalocean_droplet" "agent" {
  count    = var.agent_count
  image    = "ubuntu-24-04-x64"
  name     = "ai-memory-hive-agent-${count.index + 1}"
  region   = var.region
  size     = var.agent_droplet_size
  vpc_uuid = digitalocean_vpc.hive.id
  ssh_keys = [var.ssh_pubkey_fingerprint]

  // #2438: select the load-generator bootstrap when agent_workload=="loadgen"
  // (measurement.tfvars). Default keeps the IronClaw path unchanged. The var
  // map is shared and unchanged; the loadgen template ignores ironclaw_image_url
  // (templatefile tolerates unreferenced vars) and reads only memory_private_ip
  // + agent_index, so the default hive path is byte-identical.
  user_data = templatefile(
    var.agent_workload == "loadgen"
    ? "${path.module}/cloud-init-loadgen.yaml.tpl"
    : "${path.module}/cloud-init-agent.yaml.tpl",
    {
      ironclaw_image_url = var.ironclaw_image_url
      // Agents always target memory node 1. Under Track D (memory_count>=2)
      // node 1 is a full quorum peer, so a write admitted here fans out to
      // the rest of the mesh; spreading agents across nodes is a separate
      // load-distribution concern the cert round does not need.
      memory_private_ip = digitalocean_droplet.memory[0].ipv4_address_private
      agent_index       = count.index + 1
    }
  )

  tags = ["ai-memory-hive", "ai-memory-agent"]
}

// ---------------------------------------------------------------------------
// Firewall — east-west only on :9077, ssh from operator IP only
// ---------------------------------------------------------------------------

resource "digitalocean_firewall" "hive" {
  name = "ai-memory-hive-fw"

  droplet_ids = concat(
    digitalocean_droplet.memory[*].id,
    digitalocean_droplet.agent[*].id,
  )

  // SSH from operator only — set TF_VAR_firewall_ssh_sources to the operator
  // CIDR(s). (Terraform has no `getenv`; the prior `getenv(...)` call made the
  // whole config fail to plan — fixed to a typed variable, v0.8.1 §5.2.)
  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = var.firewall_ssh_sources
  }

  // East-west on :9077 (ai-memory HTTP daemon).
  //
  // Track D: memory nodes must also reach EACH OTHER on :9077 for the
  // mutually-authenticated quorum channel (`--quorum-peers https://<peer>:9077`).
  // The memory ids are added ONLY when a mesh is actually provisioned, so the
  // memory_count=1 rule set stays byte-identical to pre-Track-D. Peer traffic
  // still never leaves the VPC and is still refused at the rustls
  // fingerprint-allowlist layer without an authorised client cert.
  inbound_rule {
    protocol   = "tcp"
    port_range = "9077"
    source_droplet_ids = var.memory_count > 1 ? concat(
      digitalocean_droplet.agent[*].id,
      digitalocean_droplet.memory[*].id,
    ) : digitalocean_droplet.agent[*].id
  }

  // Allow all outbound (agents call xAI Grok API)
  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}

// ---------------------------------------------------------------------------
// Outputs — re-used by spawn.sh + the post-run audit dump
// ---------------------------------------------------------------------------

// Node 1 keeps the historical singular output names so `spawn.sh`,
// `README-measurement.md` step 2, and `infra/pillar4-envelope/*` keep working
// unchanged at memory_count=1 AND at memory_count>=2.
output "memory_public_ip" {
  value = digitalocean_droplet.memory[0].ipv4_address
}

output "memory_private_ip" {
  value = digitalocean_droplet.memory[0].ipv4_address_private
}

output "agent_ips" {
  value = digitalocean_droplet.agent[*].ipv4_address
}

// Track D: the full substrate roster. `federate.sh` consumes this to mint
// per-node certs (SAN = the node's private IP), push each node its bundle,
// and write the peer list every OTHER node must dial. Emitted at every
// memory_count (a 1-element list when federation is off) so the consumer
// never has to branch on the count.
output "memory_nodes" {
  description = "Per-node substrate roster: index, name, public + private IPv4, federation identity, and the https peer URL other nodes dial."
  value = [
    for i, d in digitalocean_droplet.memory : {
      index        = i + 1
      name         = d.name
      public_ip    = d.ipv4_address
      private_ip   = d.ipv4_address_private
      fed_identity = "ai:hive-memory-${i + 1}"
      peer_url     = "https://${d.ipv4_address_private}:9077"
    }
  ]
}

output "memory_public_ips" {
  value = digitalocean_droplet.memory[*].ipv4_address
}

output "memory_private_ips" {
  value = digitalocean_droplet.memory[*].ipv4_address_private
}

output "federation_enabled" {
  description = "True when a real multi-node federated mesh was provisioned (memory_count >= 2), i.e. when Track D assertions are runnable against this hive."
  value       = var.memory_count > 1
}

output "monthly_cost_estimate_usd" {
  value = format(
    "memory(%.2fx%d) + agents(%.2fx%d) = %.2f/month",
    17.41,
    var.memory_count,
    8.70,
    var.agent_count,
    (17.41 * var.memory_count) + (8.70 * var.agent_count),
  )
}
