# ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
# Security All-in-One CWE — Makefile
# Usage: make <target> TARGET=https://example.com

SHELL := /bin/bash
.DEFAULT_GOAL := help
SCAN_DATE := $(shell date +%Y%m%d-%H%M%S)

export TARGET ?= https://example.com
export DOMAIN ?= $(shell echo $(TARGET) | sed -E 's|https?://||;s|/.*||;s|:.*||')
export CODE ?= .
export REPO ?= .
export BIN ?= /dev/null
export BIN_DIR ?= .
export IMAGE ?= alpine:latest
export RATE_LIMIT ?= 50
export SCAN_DATE
export LLM_MODEL ?= gpt-3.5-turbo
export LLM_TYPE ?= openai

.PHONY: help setup run full dast sqli ssti dns sast secrets sca binary llm         zap-gui report summary defectdojo-import clean nuke

help: ## Show this help
	@echo "Security All-in-One CWE — Bug Bounty Testing Suite"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

setup: ## Pull all Docker images
	@echo "Pulling Docker images..."
	docker compose pull --ignore-buildable
	@echo "Building custom images..."
	docker compose build
	@echo "Setup complete!"

run: ## Run ALL scans (DAST+DNS+SAST+Secrets+SCA) on TARGET
	./runner.sh $(TARGET) --domain $(DOMAIN) --code $(CODE) --repo $(REPO) \
		--rate-limit $(RATE_LIMIT)

full: ## Run ALL scans in thorough mode (slower)
	./runner.sh $(TARGET) --domain $(DOMAIN) --code $(CODE) --repo $(REPO) \
		--rate-limit $(RATE_LIMIT) --full

# ── Individual tool targets ─────────────────────────────
dast: ## DAST scan only (Nuclei + ZAP) — TARGET required
	./runner.sh $(TARGET) --only nuclei,zap,zap-full

sqli: ## SQL Injection only (SQLMap) — TARGET required
	./runner.sh $(TARGET) --only sqlmap

ssti: ## SSTI scan only (SSTImap) — TARGET required
	./runner.sh $(TARGET) --only sstimap

dns: ## Subdomain takeover scan — DOMAIN required
	./runner.sh --domain $(DOMAIN) --only dnsreaper,subdominator

sast: ## SAST scan (Semgrep) — CODE=path required
	./runner.sh dummy --code $(CODE) --only semgrep

secrets: ## Secrets scan (Gitleaks + TruffleHog) — REPO=path required
	./runner.sh dummy --repo $(REPO) --only gitleaks,trufflehog

sca: ## SCA scan (Trivy + DependencyCheck) — CODE=path required
	./runner.sh dummy --code $(CODE) --only trivy,dependency-check

sca-image: ## SCA image scan — IMAGE=name required
	docker compose run --rm trivy-image

binary: ## Binary analysis (cwe_checker) — BIN=path required
	./runner.sh dummy --binary $(BIN) --only cwe-checker

llm: ## LLM prompt injection (garak) — LLM_MODEL + API key required
	./runner.sh dummy --llm-model $(LLM_MODEL) --llm-type $(LLM_TYPE) --only garak

# ── Reporting ───────────────────────────────────────────
zap-gui: ## Launch ZAP GUI (port 8080)
	docker compose --profile gui up zap-gui

report: ## Merge all reports into unified JSON
	python3 scripts/merge-reports.py --output reports/unified-report-$(SCAN_DATE).json

summary: ## Generate CWE summary from all reports
	python3 scripts/cwe-summary.py

defectdojo: ## Start DefectDojo dashboard (port 8443)
	docker compose --profile defectdojo up -d

defectdojo-import: ## Import all reports into DefectDojo
	bash scripts/defectdojo-import.sh $(SCAN_DATE)

# ── Maintenance ─────────────────────────────────────────
clean: ## Remove all reports
	find reports/ -type f -name '*.json' -o -name '*.html' -o -name '*.txt' | xargs rm -f
	@echo "Reports cleaned."

nuke: ## Remove all reports + Docker volumes + images (DESTRUCTIVE)
	@echo "⚠️  This will delete all data. Press Ctrl+C to abort."
	@sleep 3
	docker compose --profile defectdojo --profile gui down -v --rmi local
	$(MAKE) clean
	@echo "Everything nuked."
