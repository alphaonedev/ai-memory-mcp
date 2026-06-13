# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# do-1461 baseline — single entrypoint. 0->60 is:
#
#     export DIGITALOCEAN_TOKEN=...        # DO API token (apply/destroy only)
#     export OPENROUTER_API_KEY=...        # peer chat LLM (ROTATED key)
#     export XAI_API_KEY=...               # agent grok NHI driver LLM
#     make seed up provision validate test
#
# Every target is idempotent and re-runnable. Provisioning is push-based over
# SSH; nothing is installed on the operator host beyond the CLI prereqs below.
SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

TF_DIR   := terraform
PROV     := provision
VALIDATE := validate
TEST     := test
ATLAS    := atlas

# Provisioning runs in this exact order — each step is deterministic + idempotent.
PROV_STEPS := \
  00_render_inventory.sh \
  05_wait_ssh.sh \
  10_binary.sh \
  15_tls.sh \
  20_pg_age.sh \
  25_ollama_embed.sh \
  30_config.sh \
  45_zero_touch.sh \
  46_batman.sh \
  50_federation.sh

.PHONY: help seed up inventory provision validate test atlas report down preflight require-token

help: ## Show this help
	@awk 'BEGIN{FS=":.*##"; printf "\ndo-1461 baseline targets:\n\n"} \
	  /^[a-zA-Z0-9_-]+:.*##/{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@printf "\nflow: make seed up provision validate test   (teardown: make down)\n\n"

preflight: ## Verify operator-host CLI prerequisites are present
	@for b in terraform jq openssl ssh scp curl cargo; do \
	  command -v $$b >/dev/null 2>&1 || { echo "FATAL: missing prerequisite '$$b'"; exit 1; }; \
	done
	@echo "preflight OK (terraform jq openssl ssh scp curl cargo present)"

require-token:
	@[ -n "$${DIGITALOCEAN_TOKEN:-}" ] || { echo "FATAL: export DIGITALOCEAN_TOKEN before apply/destroy"; exit 1; }

seed: preflight ## terraform init + validate (no cloud mutation)
	cd $(TF_DIR) && terraform init -input=false && terraform validate
	@echo "seed OK — terraform initialized + config valid"

up: preflight require-token ## terraform apply (creates the fleet) + render inventory
	cd $(TF_DIR) && terraform apply -input=false -auto-approve
	bash $(PROV)/00_render_inventory.sh
	@echo "up OK — fleet applied, inventory rendered"

inventory: ## Re-render inventory.json from terraform state
	bash $(PROV)/00_render_inventory.sh

provision: preflight ## Push-based 0->60 bring-up (binary/PG+AGE/embed/config/TLS/federation)
	@for step in $(PROV_STEPS); do \
	  echo "==> $(PROV)/$$step"; \
	  bash $(PROV)/$$step || { echo "FATAL: $$step failed"; exit 1; }; \
	done
	@echo "provision OK — fleet is 0->60"

validate: ## Run the verification harness (machine+human report; non-zero on any FAIL)
	bash $(VALIDATE)/run.sh

test: validate ## Run the full-spectrum test suite (P3) — gated behind a green validate
	bash $(TEST)/run.sh

atlas: validate ## Run the Atlas Corpus recall+scale test (#1535) — attested ingest, gated behind a green validate
	bash $(ATLAS)/run.sh

report: ## Print the most recent verification + full-spectrum-test + atlas reports
	@d="$${DO_1461_RUN_DIR:-../../.local-runs/do-1461}/reports"; \
	  for pfx in verify test atlas; do \
	    latest="$$(ls -t $$d/$$pfx-*.json 2>/dev/null | head -1)"; \
	    [ -n "$$latest" ] && { echo "latest $$pfx report: $$latest"; cat "$$latest"; echo; } \
	      || echo "no $$pfx report yet — run 'make $$([ $$pfx = verify ] && echo validate || ([ $$pfx = atlas ] && echo atlas || echo test))'"; \
	  done

down: preflight require-token ## terraform destroy (DESTRUCTIVE) + wipe per-fleet state for a clean rebuild
	@echo "About to DESTROY the entire do-1461 fleet. Ctrl-C within 5s to abort."; sleep 5
	-cd $(TF_DIR) && terraform destroy -input=false -auto-approve
	@$(MAKE) --no-print-directory clean-state
	@echo "down OK — fleet destroyed (note: a region's DEFAULT VPC cannot be deleted by DO and persists as an empty, dataless container; it is reused on the next 'up' and does not affect reproducibility)"

clean-state: ## wipe per-fleet IP-bound generated state (TLS/secrets/render/inventory) so a fresh provision regenerates certs/secrets for the NEW fleet's IPs
	@RUN="$${DO_1461_RUN_DIR:-../../.local-runs/do-1461}"; \
	  rm -rf "$$RUN/tls" "$$RUN/secrets" "$$RUN/render" "$$RUN/inventory.json"; \
	  echo "clean-state OK — wiped $$RUN/{tls,secrets,render,inventory.json} (reports/ retained). REQUIRED between a teardown and a fresh rebuild: TLS server certs embed the fleet's per-node IPs (Leg-3 verify-full), so reusing them across a destroy+apply (which reassigns IPs) fails cert validation. A fresh provision now regenerates everything bound to the new IPs — the reproducible clean-room contract."
