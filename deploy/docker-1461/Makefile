# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# docker-1461 — single 0→60 entrypoint for the reproducible full-spectrum
# test mesh (2 IronClaw peers + PostgreSQL/AGE/pgvector, TLS+mTLS+zero-touch).
#
# Every concrete value lives in provision/lib.sh (env-overridable, agnostic);
# this Makefile only sequences the idempotent provision steps. Peers can
# reproduce the entire environment AND results with:
#
#     set -a; . ~/.env; set +a        # OPENROUTER_API_KEY (LLM + HTTP token)
#     make -C deploy/docker-1461 0to60
#
# Targets that drive `docker compose` (up/down/validate/test/...) auto-source
# ~/.env so OPENROUTER_API_KEY is present; it is never written to any file.

SHELL := /bin/bash
.DEFAULT_GOAL := help

PROV := provision
# Source ~/.env (if present) into the recipe shell for compose secrets.
ENVLOAD := set -a; [ -f $$HOME/.env ] && . $$HOME/.env; set +a;

.PHONY: help seed build tls zerotouch up provision validate test report \
        ps logs down clean 0to60 all

help: ## Show this help
	@awk 'BEGIN{FS=":.*##"} /^[a-zA-Z0-9_-]+:.*##/{printf "  \033[36m%-12s\033[0m %s\n",$$1,$$2}' $(MAKEFILE_LIST)

# --- individual provision steps -------------------------------------------
seed: ## Render run-dir tree, PG secret, init-age.sql, campaign.env
	@$(PROV)/00_seed.sh

build: ## Build PG/AGE/pgvector + ai-memory daemon images
	@$(PROV)/10_build.sh

tls: ## Generate CA + per-peer server/client certs + mTLS allowlist
	@$(PROV)/40_tls.sh

zerotouch: ## Mint CA, export bundle, enroll each peer (credential + key)
	@$(PROV)/45_zero_touch.sh

up: ## docker compose up + gate on PG/peer health (needs ~/.env)
	@$(ENVLOAD) $(PROV)/50_up.sh

# --- composite flows ------------------------------------------------------
provision: seed tls zerotouch up ## Seed → TLS → zero-touch → bring up (no rebuild)

0to60: build provision validate test report ## Full clean build → validate → test → report
all: 0to60 ## Alias for 0to60

validate: ## Run the validation harness → machine+human report
	@$(ENVLOAD) if [ -x validate/run.sh ]; then validate/run.sh; \
	  else echo "[make] validate/run.sh not present yet (authored in D5)"; fi

test: ## Run the full-spectrum test harness → results
	@$(ENVLOAD) if [ -x test/run.sh ]; then test/run.sh; \
	  else echo "[make] test/run.sh not present yet (authored in D6)"; fi

report: ## Print the location of the generated reports
	@$(PROV)/lib.sh >/dev/null 2>&1 || true; \
	  . $(PROV)/lib.sh; echo "reports: $$REPORTS_DIR"; ls -la "$$REPORTS_DIR" 2>/dev/null || true

# --- inspection + teardown ------------------------------------------------
ps: ## Show mesh container status
	@$(ENVLOAD) . $(PROV)/lib.sh; dc ps

logs: ## Tail mesh logs (CTRL-C to stop)
	@$(ENVLOAD) . $(PROV)/lib.sh; dc logs -f --tail 80

down: ## Stop + remove the mesh (keeps images; drops volumes)
	@$(ENVLOAD) . $(PROV)/lib.sh; dc down -v --remove-orphans

clean: down ## Teardown + remove the gitignored run dir (DESTROYS keys/certs/creds)
	@. $(PROV)/lib.sh; \
	  echo "[make] removing run dir $$RUN_DIR"; rm -rf "$$RUN_DIR"
