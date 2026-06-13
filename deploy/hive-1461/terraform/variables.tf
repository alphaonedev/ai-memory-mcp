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
  default     = "hive-1461"
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

# -----------------------------------------------------------------------------
# The fleet. Map key == hostname == DO droplet name, following the
# function-encoded convention hive-<function>-<region>-<NN>. Each node declares
# its role (peer | agent | ctrl), DO region slug, and size slug.
#
# Baseline default (7 nodes):
#   - 3 peers (federated PG+AGE substrate), 2 regions  -> cross-region quorum W=2
#   - 3 agents (xAI grok-4.3 NHI drivers)
#   - 1 control (loadgen / chaos / orchestration)
#
# Scale reproducibly by editing this map (or overriding via -var-file).
# -----------------------------------------------------------------------------
variable "nodes" {
  description = "The complete fleet. Key is the hostname; value declares role/region/size."
  type = map(object({
    role   = string # peer | agent | ctrl
    region = string # nyc3 | sfo2 | ...
    size   = string # DO size slug
  }))

  default = {
    "hive-peer-nyc3-01"  = { role = "peer", region = "nyc3", size = "s-4vcpu-8gb" }
    "hive-peer-nyc3-02"  = { role = "peer", region = "nyc3", size = "s-4vcpu-8gb" }
    "hive-peer-sfo2-01"  = { role = "peer", region = "sfo2", size = "s-4vcpu-8gb" }
    "hive-agent-nyc3-01" = { role = "agent", region = "nyc3", size = "s-1vcpu-2gb" }
    "hive-agent-nyc3-02" = { role = "agent", region = "nyc3", size = "s-1vcpu-2gb" }
    "hive-agent-nyc3-03" = { role = "agent", region = "nyc3", size = "s-1vcpu-2gb" }
    "hive-ctrl-nyc3-01"  = { role = "ctrl", region = "nyc3", size = "s-8vcpu-16gb" }
  }

  validation {
    condition     = alltrue([for n in values(var.nodes) : contains(["peer", "agent", "ctrl"], n.role)])
    error_message = "Every node role must be one of: peer, agent, ctrl."
  }
}
