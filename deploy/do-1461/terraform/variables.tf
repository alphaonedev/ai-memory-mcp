# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# Baseline fleet, declared as data. A peer reviewer reads the entire test
# environment topology here: which nodes exist, their function, region, and
# size. Changing the fleet is a data edit, not a code edit — that is what
# makes the environment reproducible and peer-auditable.

variable "campaign" {
  description = "Campaign tag applied to every resource (drives firewall east-west rule + cleanup)."
  type        = string
  default     = "do-1461"
}

variable "image" {
  description = "Base droplet image slug. Pinned for reproducibility."
  type        = string
  default     = "ubuntu-24-04-x64"
}

variable "ssh_key_fingerprint" {
  description = "MD5 fingerprint of the DO-registered SSH key authorized on every droplet (operator key)."
  type        = string
  default     = "bf:0b:e1:92:6f:ea:0d:1d:e4:96:ee:ac:71:73:ed:4e" # ai-memory-ai2ai-gate
}

variable "ssh_source_addresses" {
  description = "CIDRs permitted to reach :22. Default is open; tighten to the operator/CI egress for production-grade isolation."
  type        = list(string)
  default     = ["0.0.0.0/0", "::/0"]
}

variable "federation_port" {
  description = "ai-memory HTTPS federation / API port (mTLS)."
  type        = number
  default     = 9077
}

variable "harness_source_addresses" {
  description = <<-EOT
    CIDRs — in ADDITION to campaign east-west (source_tags) — permitted to reach
    the mTLS federation/API port (:9077). The push-based validate/test harness
    runs from the operator/CI host, which is NOT a campaign member, so that
    host's egress must be allowlisted here to drive the harness. The port is
    mTLS-client-auth + x-api-key protected, so allowlisting a specific host is
    defense-in-depth, not the trust boundary. Default is empty (campaign-only,
    maximum-secure); a peer reviewer sets this to their own egress /32 to
    reproduce. NEVER set to 0.0.0.0/0 for a maximum-secure reference run.
  EOT
  type        = list(string)
  default     = []
}

variable "pg_port" {
  description = "Regional PostgreSQL 18.4 + AGE 1.7.0 substrate port (TLS, daemon->PG leg). East-west within a region's private VPC only."
  type        = number
  default     = 5432
}

# -----------------------------------------------------------------------------
# The fleet. Map key == hostname == DO droplet name, following the
# function-encoded convention <campaign>-<function>-<region>-<NN>. Each node
# declares its role (peer | pg | agent | ctrl), DO region slug, and size slug.
#
# do-1461 GRAND SLAM topology (15 nodes) — the Secure Enterprise Federated
# Reference Architecture: a 3-region AI Agent Hive. Each region is a
# self-contained substrate cluster of 1 regional PostgreSQL 18.4 + Apache
# AGE 1.7.0 + pgvector 0.8.2 node, 3 ai-memory daemon peers, and 1 agent (an
# NHI client driver). A region's peers reach THEIR regional pg over that
# region's private VPC under sslmode=verify-full (daemon->PG leg); the 9 peers
# federate into ONE mesh across all three regions over public IPs secured by
# mTLS + per-message Ed25519 signing + nonce anti-replay + CA-rooted zero-touch
# peer enrollment. Every node runs the Batman-active maximum-secure posture.
#
#   per region (x3: nyc3 US-East, fra1 EU-Central, sgp1 Asia-SE):
#     - 3 peers (ai-memory daemon, sal,sal-postgres) -> federation mesh members
#     - 1 pg    (regional PostgreSQL 18.4 + Apache AGE 1.7.0 + pgvector 0.8.2)
#     - 1 agent (NHI client: xAI grok-4.3 driver; pure mTLS client, NOT a mesh
#                member) -> exercises the a2a + ai_nhi full-spectrum groups
#   => 9 peers + 3 regional pg + 3 agents = 15 nodes. Federation is EVENTUAL
#      (async catch-up); the synchronous write quorum is a small durability
#      gate (lib.sh FED_SYNC_QUORUM_W, default 2), derived by quorum_writes() —
#      NOT a cross-region majority. Convergence is proven by the catch-up window.
#
# Scale/region reproducibly by editing this map (or overriding via -var-file).
# The provision toolkit derives everything (VPC-per-region, per-region pg
# reachability, quorum CSV, fed identities) from this declaration — no node
# count, region, or quorum size is hardcoded elsewhere.
# -----------------------------------------------------------------------------
variable "nodes" {
  description = "The complete fleet. Key is the hostname; value declares role/region/size."
  type = map(object({
    role   = string # peer | pg | agent | ctrl
    region = string # nyc3 | fra1 | sgp1 | ...
    size   = string # DO size slug
  }))

  default = {
    # --- region 1: nyc3 (US-East) ---
    "do-1461-peer-nyc3-01"  = { role = "peer", region = "nyc3", size = "s-4vcpu-8gb" }
    "do-1461-peer-nyc3-02"  = { role = "peer", region = "nyc3", size = "s-4vcpu-8gb" }
    "do-1461-peer-nyc3-03"  = { role = "peer", region = "nyc3", size = "s-4vcpu-8gb" }
    "do-1461-pg-nyc3-01"    = { role = "pg", region = "nyc3", size = "s-4vcpu-8gb" }
    "do-1461-agent-nyc3-01" = { role = "agent", region = "nyc3", size = "s-1vcpu-2gb" }
    # --- region 2: fra1 (EU-Central) ---
    "do-1461-peer-fra1-01"  = { role = "peer", region = "fra1", size = "s-4vcpu-8gb" }
    "do-1461-peer-fra1-02"  = { role = "peer", region = "fra1", size = "s-4vcpu-8gb" }
    "do-1461-peer-fra1-03"  = { role = "peer", region = "fra1", size = "s-4vcpu-8gb" }
    "do-1461-pg-fra1-01"    = { role = "pg", region = "fra1", size = "s-4vcpu-8gb" }
    "do-1461-agent-fra1-01" = { role = "agent", region = "fra1", size = "s-1vcpu-2gb" }
    # --- region 3: sgp1 (Asia-SE) ---
    "do-1461-peer-sgp1-01"  = { role = "peer", region = "sgp1", size = "s-4vcpu-8gb" }
    "do-1461-peer-sgp1-02"  = { role = "peer", region = "sgp1", size = "s-4vcpu-8gb" }
    "do-1461-peer-sgp1-03"  = { role = "peer", region = "sgp1", size = "s-4vcpu-8gb" }
    "do-1461-pg-sgp1-01"    = { role = "pg", region = "sgp1", size = "s-4vcpu-8gb" }
    "do-1461-agent-sgp1-01" = { role = "agent", region = "sgp1", size = "s-1vcpu-2gb" }
  }

  validation {
    condition     = alltrue([for n in values(var.nodes) : contains(["peer", "pg", "agent", "ctrl"], n.role)])
    error_message = "Every node role must be one of: peer, pg, agent, ctrl."
  }

  validation {
    # Exactly one regional pg substrate per region that has any node.
    condition = alltrue([
      for r in distinct([for n in values(var.nodes) : n.region]) :
      length([for n in values(var.nodes) : n if n.role == "pg" && n.region == r]) == 1
    ])
    error_message = "Each region must declare exactly one pg node (one regional PostgreSQL+AGE+pgvector substrate per region)."
  }

  validation {
    # Every peer's region must have a pg node to bind to (no orphan peers).
    condition = alltrue([
      for n in values(var.nodes) : (
        n.role != "peer" ? true :
        length([for m in values(var.nodes) : m if m.role == "pg" && m.region == n.region]) == 1
      )
    ])
    error_message = "Every peer must sit in a region that has exactly one pg node."
  }
}
