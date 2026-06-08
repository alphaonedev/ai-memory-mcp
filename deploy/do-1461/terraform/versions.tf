# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# Reproducible DO test-environment baseline (EPIC #1461, global tracker #1513).
# Pinned provider versions so a peer reviewer resolves the identical plugin
# graph. `terraform init` against this file is deterministic given the lock.

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.40"
    }
  }
}

# Token is read from the DIGITALOCEAN_TOKEN (or DIGITALOCEAN_ACCESS_TOKEN)
# environment variable by the provider. NEVER commit a token to this repo.
# The Makefile sources it from the local doctl config at apply time so the
# secret never lands in a tracked file.
provider "digitalocean" {}
