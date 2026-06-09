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
  description = "Peer hostnames -> public IP (ai-memory daemon, W=2 quorum mesh)."
  value       = { for name, d in digitalocean_droplet.node : name => d.ipv4_address if var.nodes[name].role == "peer" }
}

output "pg" {
  description = "Shared PG18.4/AGE1.7.0 substrate: hostname -> {public_ip, private_ip}. Peers reach it on the private VPC IP over TLS."
  value = {
    for name, d in digitalocean_droplet.node : name => {
      public_ip  = d.ipv4_address
      private_ip = d.ipv4_address_private
    } if var.nodes[name].role == "pg"
  }
}
