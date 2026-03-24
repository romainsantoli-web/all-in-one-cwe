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

.PHONY: help setup run full dast sqli ssti dns sast secrets sca binary llm \
       recon fuzz waf tls cors network fingerprint api cloud \
       xss jwt classic-scan oob amass-enum js-analysis dns-toolkit screenshot \
       crlf ssrf container-lint frontend-sca log4shell osint openapi proto-pollution graphql-deep cms \
       idor auth-bypass user-enum notif-inject redirect-cors oidc-audit bypass-403-adv ssrf-scan xss-scan api-discovery secret-leak python-scanners \
       auth-extract auth-scan \
       scan-smart prefect-ui prefect-status report-smart \
       websocket-scan cache-deception slowloris smuggler checkov restler \
       zap-gui report summary defectdojo-import clean nuke

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

# ── Prefect orchestrator ────────────────────────────────
scan-smart: ## Run DAG-orchestrated scan (Prefect — parallel + retries)
	python -m orchestrator.flows.scan_flow --target $(TARGET) --domain $(DOMAIN) \
		--code $(CODE) --repo $(REPO) --rate-limit $(RATE_LIMIT)

scan-smart-dry: ## Dry-run the Prefect DAG (no actual scanning)
	python -m orchestrator.flows.scan_flow --target $(TARGET) --domain $(DOMAIN) --dry-run

prefect-ui: ## Start Prefect server UI (port 4200)
	docker compose --profile orchestrator up -d prefect-server
	@echo "Prefect UI: http://localhost:4200"

prefect-status: ## Check Prefect server status
	@curl -s http://localhost:4200/api/health 2>/dev/null && echo "Prefect server is running" || echo "Prefect server is not running"

# ── Smart reporting (Phase 2) ───────────────────────────
report-smart: ## Generate intelligent report (dedup + CVSS + AI + dashboard)
	python3 scripts/dedup_engine.py
	python3 scripts/scoring_engine.py
	python3 scripts/ai_analyzer.py
	python3 scripts/generate_dashboard.py
	@echo "Dashboard: reports/dashboard.html"

# ── Phase 3: New tool targets ───────────────────────────
websocket-scan: ## WebSocket security scan — TARGET required
	docker compose --profile python-scanners run --rm websocket-scanner

cache-deception: ## Web Cache Deception scan — TARGET required
	docker compose --profile python-scanners run --rm cache-deception

slowloris: ## Slowloris detection (non-destructive) — TARGET required
	docker compose --profile python-scanners run --rm slowloris-check

smuggler: ## HTTP Request Smuggling scan — TARGET required
	docker compose --profile web-advanced run --rm smuggler

checkov: ## IaC security scan (Terraform, K8s, Docker) — CODE required
	docker compose --profile iac run --rm checkov

restler: ## REST API fuzzing (Microsoft RESTler) — needs OpenAPI spec
	docker compose --profile api-fuzzing run --rm restler

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

# ── New tool targets ────────────────────────────────────
recon: ## Recon scan (httpx + subfinder + naabu + katana) — DOMAIN required
	./runner.sh $(TARGET) --domain $(DOMAIN) --only httpx,subfinder,naabu,katana

fuzz: ## Directory/param fuzzing (ffuf + feroxbuster + arjun) — TARGET required
	./runner.sh $(TARGET) --only ffuf,feroxbuster,arjun

waf: ## WAF detection + bypass (wafw00f + bypass-403) — TARGET required
	./runner.sh $(TARGET) --only wafw00f,bypass-403

tls: ## TLS/SSL audit (testssl.sh) — TARGET required
	./runner.sh $(TARGET) --only testssl

cors: ## CORS misconfiguration scan (CORScanner) — DOMAIN required
	./runner.sh $(TARGET) --domain $(DOMAIN) --only corscanner

network: ## Network port scan (nmap) — DOMAIN required
	./runner.sh $(TARGET) --domain $(DOMAIN) --only nmap

fingerprint: ## Tech fingerprinting (WhatWeb) — TARGET required
	./runner.sh $(TARGET) --only whatweb

api: ## API scan (graphw00f GraphQL) — TARGET required
	./runner.sh $(TARGET) --only graphw00f

cloud: ## Cloud storage enum (cloud_enum) — DOMAIN required
	./runner.sh $(TARGET) --domain $(DOMAIN) --only cloud-enum

# ── New Round 2 tool targets ────────────────────────────
xss: ## XSS scan (Dalfox) — TARGET required
	./runner.sh $(TARGET) --only dalfox

jwt: ## JWT token testing (jwt_tool) — JWT_TOKEN env required
	./runner.sh $(TARGET) --only jwt-tool

classic-scan: ## Classic web scan (Nikto) — TARGET required
	./runner.sh $(TARGET) --only nikto

oob: ## Out-of-band interaction (Interactsh)
	./runner.sh $(TARGET) --only interactsh

amass-enum: ## OWASP Amass subdomain enum — DOMAIN required
	./runner.sh $(TARGET) --domain $(DOMAIN) --only amass

js-analysis: ## JavaScript secret extraction (JSLuice) — TARGET required
	./runner.sh $(TARGET) --only jsluice

dns-toolkit: ## DNS toolkit (DNSx) — DOMAIN required
	./runner.sh $(TARGET) --domain $(DOMAIN) --only dnsx

screenshot: ## Web screenshot (Gowitness) — TARGET required
	./runner.sh $(TARGET) --only gowitness

crlf: ## CRLF injection scan (CRLFuzz) — TARGET required
	./runner.sh $(TARGET) --only crlfuzz

ssrf: ## SSRF exploitation (SSRFmap) — TARGET required
	./runner.sh $(TARGET) --only ssrfmap

container-lint: ## Container best practices (Dockle) — IMAGE required
	./runner.sh dummy --image $(IMAGE) --only dockle

frontend-sca: ## Frontend JS SCA (RetireJS) — CODE=path required
	./runner.sh dummy --code $(CODE) --only retirejs

log4shell: ## Log4Shell detection (log4j-scan) — TARGET required
	./runner.sh $(TARGET) --only log4j-scan

osint: ## OSINT harvesting (theHarvester) — DOMAIN required
	./runner.sh $(TARGET) --domain $(DOMAIN) --only theharvester

openapi: ## OpenAPI spec audit (Cherrybomb) — needs reports/cherrybomb/openapi.json
	./runner.sh $(TARGET) --only cherrybomb

proto-pollution: ## Prototype pollution scan (ppmap) — TARGET required
	./runner.sh $(TARGET) --only ppmap

graphql-deep: ## GraphQL deep scan (Clairvoyance) — TARGET required
	./runner.sh $(TARGET) --only clairvoyance

cms: ## CMS detection + vulns (CMSeeK) — TARGET required
	./runner.sh $(TARGET) --only cmseek

# ── Python Scanners ─────────────────────────────────────
idor: ## IDOR scanner (CWE-639) — TARGET + AUTH_TOKEN required
	./runner.sh $(TARGET) --only idor-scanner

auth-bypass: ## Auth bypass scanner (CWE-287/284/915) — TARGET required
	./runner.sh $(TARGET) --only auth-bypass

user-enum: ## User enumeration (CWE-203/204) — TARGET required
	./runner.sh $(TARGET) --only user-enum

notif-inject: ## Notification injection (CWE-74/79/93) — TARGET + AUTH_TOKEN required
	./runner.sh $(TARGET) --only notif-inject

redirect-cors: ## Open redirect + CORS (CWE-601/942) — TARGET required
	./runner.sh $(TARGET) --only redirect-cors

oidc-audit: ## OIDC/Keycloak audit (CWE-200/287/522) — TARGET required
	./runner.sh $(TARGET) --only oidc-audit

python-scanners: ## Run ALL Python scanners — TARGET + AUTH_TOKEN required
	./runner.sh $(TARGET) --only idor-scanner --only auth-bypass --only user-enum --only notif-inject --only redirect-cors --only oidc-audit --only bypass-403-advanced --only ssrf-scanner --only xss-scanner --only api-discovery --only secret-leak

bypass-403-adv: ## 403 bypass + RPC discovery (CWE-284) — TARGET required
	./runner.sh $(TARGET) --only bypass-403-advanced

ssrf-scan: ## SSRF scanner (CWE-918) — TARGET required
	./runner.sh $(TARGET) --only ssrf-scanner

xss-scan: ## XSS scanner (CWE-79/693/1336) — TARGET + AUTH_TOKEN required
	./runner.sh $(TARGET) --only xss-scanner

api-discovery: ## API discovery (CWE-200/540) — JS bundles + endpoint enum — TARGET required
	./runner.sh $(TARGET) --only api-discovery

secret-leak: ## Secret leak scanner (CWE-312/540/615) — response + JS secrets — TARGET required
	./runner.sh $(TARGET) --only secret-leak

auth-extract: ## Launch Chrome (clean profile) + extract auth → auth.env
	python3 tools/python-scanners/auth_extractor.py --target $(TARGET) --output auth.env --json --launch-chrome --wait-login

auth-scan: ## Extract auth + run ALL Python scanners (one-shot)
	./runner.sh $(TARGET) --auto-auth

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
