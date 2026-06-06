# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# Reproducible DO baseline — resources. The fleet is materialized from
# var.nodes via for_each, so the plan is a pure function of the declared data.

locals {
  # Distinct regions present in the fleet -> one VPC per region.
  regions = distinct([for n in values(var.nodes) : n.region])

  # DO VPC ip_range must be unique per account, so each region gets its own
  # deterministic, non-overlapping /16: 10.<10+sorted_index>.0.0/16. Sorting
  # makes the assignment a stable pure function of the region set (nyc3 -> 10.10,
  # sfo2 -> 10.11, …) so re-plans don't churn already-created VPCs.
  region_cidr = {
    for idx, r in sort(local.regions) : r => "10.${10 + idx}.0.0/16"
  }
}

# -----------------------------------------------------------------------------
# One VPC per region. DO VPCs are regional; cross-region federation therefore
# rides public IPs secured by mTLS + the campaign firewall (below), not private
# networking. Same-region peers/agents get private east-west via the VPC.
# -----------------------------------------------------------------------------
resource "digitalocean_vpc" "regional" {
  for_each = toset(local.regions)

  name     = "${var.campaign}-vpc-${each.key}"
  region   = each.key
  ip_range = local.region_cidr[each.key]
}

# -----------------------------------------------------------------------------
# Droplets — one per declared node. Name == hostname == map key. cloud-init
# pins the hostname and lays down the base layer; the app layer is installed
# idempotently by the push-based provision/ scripts (so it can be re-run).
# -----------------------------------------------------------------------------
resource "digitalocean_droplet" "node" {
  for_each = var.nodes

  image    = var.image
  name     = each.key
  region   = each.value.region
  size     = each.value.size
  vpc_uuid = digitalocean_vpc.regional[each.value.region].id
  ssh_keys = [var.ssh_key_fingerprint]

  user_data = templatefile("${path.module}/cloud-init/base.yaml.tpl", {
    hostname = each.key
    role     = each.value.role
    campaign = var.campaign
  })

  tags = [var.campaign, "hive-${each.value.role}"]
}

# -----------------------------------------------------------------------------
# Campaign firewall. SSH from operator CIDRs; federation port east-west among
# campaign members (tag-matched so it works across regions on public IPs);
# all egress (agents call xAI, peers call OpenRouter, apt, etc.).
# -----------------------------------------------------------------------------
resource "digitalocean_firewall" "campaign" {
  name        = "${var.campaign}-fw"
  droplet_ids = [for d in digitalocean_droplet.node : d.id]

  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = var.ssh_source_addresses
  }

  # ai-memory mTLS federation/API, east-west among campaign nodes only.
  inbound_rule {
    protocol    = "tcp"
    port_range  = tostring(var.federation_port)
    source_tags = [var.campaign]
  }

  # ICMP among campaign nodes (reachability probes).
  inbound_rule {
    protocol    = "icmp"
    source_tags = [var.campaign]
  }

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
  outbound_rule {
    protocol              = "icmp"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}
