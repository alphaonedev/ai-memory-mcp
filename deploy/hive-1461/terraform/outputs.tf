# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# Outputs are the contract between Terraform and the push-based provisioning
# layer. `provision/00_render_inventory.sh` consumes `fleet` (JSON) to build
# the inventory the rest of the toolkit drives off of.

output "fleet" {
  description = "Full node inventory: hostname -> {role, region, public_ip, private_ip}."
  value = {
    for name, d in digitalocean_droplet.node : name => {
      role       = var.nodes[name].role
      region     = var.nodes[name].region
      size       = var.nodes[name].size
      public_ip  = d.ipv4_address
      private_ip = d.ipv4_address_private
    }
  }
}

output "peers" {
  description = "Peer hostnames -> public IP (federated PG+AGE substrate)."
  value       = { for name, d in digitalocean_droplet.node : name => d.ipv4_address if var.nodes[name].role == "peer" }
}

output "agents" {
  description = "Agent hostnames -> public IP (xAI grok-4.3 NHI drivers)."
  value       = { for name, d in digitalocean_droplet.node : name => d.ipv4_address if var.nodes[name].role == "agent" }
}

output "control" {
  description = "Control hostnames -> public IP (loadgen / chaos / orchestration)."
  value       = { for name, d in digitalocean_droplet.node : name => d.ipv4_address if var.nodes[name].role == "ctrl" }
}
