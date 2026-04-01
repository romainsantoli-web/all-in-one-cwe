#!/usr/bin/env bash
# Security All-in-One CWE — Runner Script
# Usage: ./runner.sh <target_url> [options]
#
# Options:
#   --domain <domain>       Domain for subdomain enumeration
#   --code <path>           Source code path for SAST
#   --repo <path>           Git repo path for secrets scanning
#   --binary <path>         Binary path for cwe_checker
#   --bin-dir <path>        Binary directory for cve-bin-tool
#   --image <name>          Docker image for Trivy scan
#   --llm-model <model>     LLM model name for garak
#   --llm-type <type>       LLM provider type for garak
#   --rate-limit <n>        Nuclei rate limit (default: 50)
#   --skip <tools>          Comma-separated list of tools to skip
#   --only <tools>          Comma-separated list of tools to run (exclusive)
#   --auth-file <path>      Path to auth.env (auto-sourced before scanning)
#   --auto-auth             Extract auth from Chrome CDP before scanning
#   --cdp-port <port>       Chrome CDP port (default: 9222)
#   --defectdojo            Start DefectDojo and import results
#   --full                  Run extended scans (slower but more thorough)
#   -h, --help              Show this help

set -euo pipefail

# ── Colors ──────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║        🛡️  Security All-in-One CWE Scanner  🛡️              ║"
    echo "║        Covering 150+ CWEs across 48 tools                  ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()   { echo -e "${YELLOW}[!]${NC} $*"; }
error()  { echo -e "${RED}[✗]${NC} $*"; }
info()   { echo -e "${BLUE}[i]${NC} $*"; }
header() { echo -e "\n${CYAN}━━━ $* ━━━${NC}"; }

usage() {
    head -20 "$0" | grep '^#' | sed 's/^# \?//'
    exit 0
}

# ── Defaults ────────────────────────────────────────────────
TARGET=""
DOMAIN=""
CODE=""
REPO=""
BINARY=""
BIN_DIR=""
IMAGE=""
LLM_MODEL="gpt-3.5-turbo"
LLM_TYPE="openai"
RATE_LIMIT=50
SKIP=""
ONLY=""
DEFECTDOJO=false
FULL=false
AUTH_FILE=""
AUTO_AUTH=false
CDP_PORT=9222
SCAN_DATE=$(date +%Y%m%d-%H%M%S)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Parse args ──────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)      usage ;;
        --domain)       DOMAIN="$2"; shift 2 ;;
        --code)         CODE="$2"; shift 2 ;;
        --repo)         REPO="$2"; shift 2 ;;
        --binary)       BINARY="$2"; shift 2 ;;
        --bin-dir)      BIN_DIR="$2"; shift 2 ;;
        --image)        IMAGE="$2"; shift 2 ;;
        --llm-model)    LLM_MODEL="$2"; shift 2 ;;
        --llm-type)     LLM_TYPE="$2"; shift 2 ;;
        --rate-limit)   RATE_LIMIT="$2"; shift 2 ;;
        --skip)         SKIP="$2"; shift 2 ;;
        --only)         ONLY="$2"; shift 2 ;;
        --auth-file)    AUTH_FILE="$2"; shift 2 ;;
        --auto-auth)    AUTO_AUTH=true; shift ;;
        --cdp-port)     CDP_PORT="$2"; shift 2 ;;
        --defectdojo)   DEFECTDOJO=true; shift ;;
        --full)         FULL=true; shift ;;
        -*)             error "Unknown option: $1"; usage ;;
        *)              TARGET="$1"; shift ;;
    esac
done

if [[ -z "$TARGET" && -z "$CODE" && -z "$REPO" && -z "$BINARY" && -z "$BIN_DIR" && -z "$IMAGE" && -z "$DOMAIN" ]]; then
    error "No target specified. Usage: $0 <target_url> [options]"
    usage
fi

# Extract domain from TARGET if not specified
if [[ -z "$DOMAIN" && -n "$TARGET" ]]; then
    DOMAIN=$(echo "$TARGET" | sed -E 's|https?://||;s|/.*||;s|:.*||')
fi

# ── Tool selection ──────────────────────────────────────────
should_run() {
    local tool="$1"
    if [[ -n "$ONLY" ]]; then
        echo ",$ONLY," | grep -qi ",$tool,"
        return $?
    fi
    if [[ -n "$SKIP" ]]; then
        echo ",$SKIP," | grep -qi ",$tool,"
        return $((1 - $?))
    fi
    return 0
}

# ── Environment export ──────────────────────────────────────
export TARGET DOMAIN SCAN_DATE RATE_LIMIT LLM_MODEL LLM_TYPE
export CODE="${CODE:-.}"
export REPO="${REPO:-.}"
export BIN="${BINARY:-/dev/null}"
export BIN_DIR="${BIN_DIR:-.}"
export IMAGE="${IMAGE:-alpine:latest}"

cd "$SCRIPT_DIR"
mkdir -p reports/{nuclei,zap,sqlmap,semgrep,gitleaks,trufflehog,trivy,cwe-checker,cve-bin-tool,garak,dnsreaper,subdominator,dependency-check,sstimap,httpx,subfinder,naabu,katana,ffuf,feroxbuster,arjun,wafw00f,bypass-403,testssl,corscanner,nmap,whatweb,graphw00f,cloud-enum,dalfox,interactsh,nikto,jwt-tool,amass,jsluice,dnsx,gowitness,crlfuzz,ssrfmap,dockle,retirejs,log4j-scan,theharvester,cherrybomb,ppmap,clairvoyance,cmseek,idor-scanner,auth-bypass,user-enum,notif-inject,redirect-cors,oidc-audit,bypass-403-advanced,ssrf-scanner,xss-scanner,api-discovery,secret-leak}

banner
info "Scan started at $(date)"
info "Target: ${TARGET:-N/A}"
info "Domain: ${DOMAIN:-N/A}"
info "Scan ID: $SCAN_DATE"
echo ""

RESULTS=()
FAILED=()

run_tool() {
    local name="$1"
    local service="$2"
    shift 2
    local profile_args=()
    local extra_args=()

    # Separate --profile from other args
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --profile) profile_args+=(--profile "$2"); shift 2 ;;
            *)         extra_args+=("$1"); shift ;;
        esac
    done

    if ! should_run "$name"; then
        info "Skipping $name (filtered)"
        return 0
    fi

    header "$name"
    log "Starting $name..."

    if docker compose ${profile_args[@]+"${profile_args[@]}"} run --rm ${extra_args[@]+"${extra_args[@]}"} "$service" 2>&1; then
        log "$name completed successfully ✓"
        RESULTS+=("$name")
    else
        warn "$name finished with warnings/errors"
        FAILED+=("$name")
    fi
}

# ── 1. DAST Scans ──────────────────────────────────────────
if [[ -n "$TARGET" ]]; then
    # Nuclei (custom templates)
    run_tool "nuclei" "nuclei"

    # Nuclei full (default templates) — slow
    if $FULL; then
        run_tool "nuclei-full" "nuclei-full"
    fi

    # ZAP baseline
    run_tool "zap" "zap-baseline"

    # ZAP full scan — slow
    if $FULL; then
        run_tool "zap-full" "zap-full"
    fi

    # SQLMap
    run_tool "sqlmap" "sqlmap"

    # SSTImap
    run_tool "sstimap" "sstimap"
fi

# ── 2. DNS / Subdomain Takeover ─────────────────────────────
if [[ -n "$DOMAIN" ]]; then
    run_tool "dnsreaper" "dnsreaper"
    run_tool "subdominator" "subdominator"
fi

# ── 3. SAST — Source Code Analysis ──────────────────────────
if [[ -d "$CODE" && "$CODE" != "." ]]; then
    run_tool "semgrep" "semgrep"
fi

# ── 4. Secrets Scanning ─────────────────────────────────────
if [[ -d "$REPO" && "$REPO" != "." ]]; then
    run_tool "gitleaks" "gitleaks"
    run_tool "trufflehog" "trufflehog"
fi

# ── 5. SCA — Dependency Scanning ────────────────────────────
if [[ -d "$CODE" && "$CODE" != "." ]]; then
    run_tool "trivy" "trivy"
    run_tool "dependency-check" "dependency-check"
fi

# Docker image scan
if [[ -n "$IMAGE" && "$IMAGE" != "alpine:latest" ]]; then
    run_tool "trivy-image" "trivy-image"
fi

# ── 6. Binary Analysis ──────────────────────────────────────
if [[ -f "$BINARY" ]]; then
    run_tool "cwe-checker" "cwe-checker"
fi

if [[ -d "$BIN_DIR" && "$BIN_DIR" != "." ]]; then
    run_tool "cve-bin-tool" "cve-bin-tool"
fi

# ── 7. LLM Prompt Injection ─────────────────────────────────
if should_run "garak" && [[ -n "${OPENAI_API_KEY:-}" || -n "${ANTHROPIC_API_KEY:-}" ]]; then
    run_tool "garak" "garak"
else
    if should_run "garak"; then
        warn "Skipping garak — no API key set (OPENAI_API_KEY or ANTHROPIC_API_KEY)"
    fi
fi

# ── 8. Recon — Subdomain & HTTP probing ─────────────────────
if [[ -n "$DOMAIN" ]]; then
    run_tool "subfinder" "subfinder"
fi

if [[ -n "$DOMAIN" ]]; then
    run_tool "httpx" "httpx" --profile recon
    run_tool "naabu" "naabu" --profile recon
fi

if [[ -n "$TARGET" ]]; then
    run_tool "katana" "katana" --profile recon
fi

# ── 9. WAF Fingerprinting ───────────────────────────────────
if [[ -n "$TARGET" ]]; then
    run_tool "wafw00f" "wafw00f"
    run_tool "bypass-403" "bypass-403" --profile waf
fi

# ── 10. Fuzzing — Directory & Parameter ──────────────────────
if [[ -n "$TARGET" ]]; then
    run_tool "ffuf" "ffuf" --profile fuzz
    run_tool "feroxbuster" "feroxbuster" --profile fuzz
    run_tool "arjun" "arjun"
fi

# ── 11. TLS/SSL Audit ───────────────────────────────────────
if [[ -n "$TARGET" ]]; then
    run_tool "testssl" "testssl"
fi

# ── 12. CORS Misconfiguration ───────────────────────────────
if [[ -n "$DOMAIN" ]]; then
    run_tool "corscanner" "corscanner"
fi

# ── 13. Network — Port Scanning ─────────────────────────────
if [[ -n "$DOMAIN" ]]; then
    run_tool "nmap" "nmap" --profile network
fi

# ── 14. Tech Fingerprinting ─────────────────────────────────
if [[ -n "$TARGET" ]]; then
    run_tool "whatweb" "whatweb"
fi

# ── 15. API Scanning ────────────────────────────────────────
if [[ -n "$TARGET" ]]; then
    run_tool "graphw00f" "graphw00f"
fi

# ── 16. Cloud Storage Enumeration ────────────────────────────
if [[ -n "$DOMAIN" ]]; then
    run_tool "cloud-enum" "cloud-enum"
fi

# ── 17. XSS Scanning ────────────────────────────────────────
if [[ -n "$TARGET" ]]; then
    run_tool "dalfox" "dalfox" --profile xss
fi

# ── 18. Out-of-Band (OOB) Interaction ───────────────────────
if should_run "interactsh"; then
    run_tool "interactsh" "interactsh" --profile oob
fi

# ── 19. Classic Web Scanner ─────────────────────────────────
if [[ -n "$TARGET" ]]; then
    run_tool "nikto" "nikto"
fi

# ── 20. JWT Token Testing ───────────────────────────────────
if should_run "jwt-tool" && [[ -n "${JWT_TOKEN:-}" ]]; then
    run_tool "jwt-tool" "jwt-tool" --profile jwt
else
    if should_run "jwt-tool"; then
        info "Skipping jwt-tool — no JWT_TOKEN set"
    fi
fi

# ── 21. OWASP Amass — Subdomain Enumeration ─────────────────
if [[ -n "$DOMAIN" ]]; then
    run_tool "amass" "amass"
fi

# ── 22. JavaScript Analysis ─────────────────────────────────
if [[ -n "$TARGET" ]]; then
    run_tool "jsluice" "jsluice" --profile js
fi

# ── 23. DNS Toolkit ─────────────────────────────────────────
if [[ -n "$DOMAIN" ]]; then
    run_tool "dnsx" "dnsx"
fi

# ── 24. Screenshot / Visual Recon ────────────────────────────
if [[ -n "$TARGET" ]]; then
    run_tool "gowitness" "gowitness" --profile screenshot
fi

# ── 25. CRLF Injection ──────────────────────────────────────
if [[ -n "$TARGET" ]]; then
    run_tool "crlfuzz" "crlfuzz"
fi

# ── 26. SSRF Exploitation ───────────────────────────────────
if should_run "ssrfmap"; then
    run_tool "ssrfmap" "ssrfmap" --profile ssrf
fi

# ── 27. Container Security Lint ──────────────────────────────
if [[ -n "$IMAGE" && "$IMAGE" != "alpine:latest" ]]; then
    run_tool "dockle" "dockle" --profile container
fi

# ── 28. Frontend SCA (RetireJS) ──────────────────────────────
if [[ -d "$CODE" && "$CODE" != "." ]]; then
    run_tool "retirejs" "retirejs" --profile frontend-sca
fi

# ── 29. Log4Shell Detection ─────────────────────────────────
if [[ -n "$TARGET" ]]; then
    run_tool "log4j-scan" "log4j-scan"
fi

# ── 30. OSINT — theHarvester ─────────────────────────────────
if [[ -n "$DOMAIN" ]]; then
    run_tool "theharvester" "theharvester" --profile osint
fi

# ── 31. OpenAPI Audit ────────────────────────────────────────
if should_run "cherrybomb" && [[ -f "reports/cherrybomb/openapi.json" ]]; then
    run_tool "cherrybomb" "cherrybomb" --profile openapi
else
    if should_run "cherrybomb"; then
        info "Skipping cherrybomb — no openapi.json in reports/cherrybomb/"
    fi
fi

# ── 32. Prototype Pollution ──────────────────────────────────
if [[ -n "$TARGET" ]]; then
    run_tool "ppmap" "ppmap" --profile prototype
fi

# ── 33. GraphQL Deep Scan ────────────────────────────────────
if [[ -n "$TARGET" ]]; then
    run_tool "clairvoyance" "clairvoyance" --profile graphql
fi

# ── 34. CMS Detection ───────────────────────────────────────
if [[ -n "$TARGET" ]]; then
    run_tool "cmseek" "cmseek" --profile cms
fi

# ── 35a. Auth Extraction (optional) ──────────────────────────────────
if [[ "$AUTO_AUTH" == true && -n "$TARGET" ]]; then
    header "Auth Extraction (CDP)"
    log "Launching Chrome with clean profile + extracting auth tokens..."
    if python3 tools/python-scanners/auth_extractor.py \
        --target "$TARGET" --output auth.env --cdp-port "$CDP_PORT" \
        --launch-chrome --wait-login --kill-chrome 2>&1; then
        AUTH_FILE="auth.env"
        log "Auth extraction successful ✓"
    else
        warn "Auth extraction failed — scanners will run without auth"
    fi
fi

# Source auth.env if available
if [[ -n "$AUTH_FILE" && -f "$AUTH_FILE" ]]; then
    log "Sourcing auth from $AUTH_FILE"
    set -a
    # shellcheck disable=SC1090
    source "$AUTH_FILE"
    set +a
fi

# ── 35b. Python Scanners — IDOR / Auth / Enum / Inject / CORS / OIDC ──
if [[ -n "$TARGET" ]]; then
    run_tool "idor-scanner" "idor-scanner" --profile python-scanners
    run_tool "auth-bypass" "auth-bypass" --profile python-scanners
    run_tool "user-enum" "user-enum" --profile python-scanners
    run_tool "notif-inject" "notif-inject" --profile python-scanners
    run_tool "redirect-cors" "redirect-cors" --profile python-scanners
    run_tool "oidc-audit" "oidc-audit" --profile python-scanners
    run_tool "bypass-403-advanced" "bypass-403-advanced" --profile python-scanners
    run_tool "ssrf-scanner" "ssrf-scanner" --profile python-scanners
    run_tool "xss-scanner" "xss-scanner" --profile python-scanners
    run_tool "api-discovery" "api-discovery" --profile python-scanners
    run_tool "secret-leak" "secret-leak" --profile python-scanners
fi

# ── 37. Brute-Forcer — Default creds + rate limit ──────────
if [[ -n "$TARGET" ]]; then
    run_tool "brute-forcer" "brute-forcer" --profile python-scanners
fi

# ── 38. Commix — OS Command Injection ──────────────────────
if [[ -n "$TARGET" ]]; then
    run_tool "commix" "commix" --profile injection
fi

# ── 39. Wapiti — DAST Web Scanner ──────────────────────────
if [[ -n "$TARGET" ]]; then
    run_tool "wapiti" "wapiti" --profile dast
fi

# ── 40. OSINT Enricher — Shodan + SearchSploit ─────────────
if [[ -n "$DOMAIN" ]]; then
    run_tool "osint-enricher" "osint-enricher" --profile python-scanners
fi

# ── 41. Masscan — Mass port scanning ───────────────────────
if [[ -n "$DOMAIN" ]]; then
    run_tool "masscan" "masscan" --profile network
fi

# ── 42. Recon-ng — OSINT framework ─────────────────────────
if [[ -n "$DOMAIN" ]]; then
    run_tool "recon-ng" "recon-ng" --profile osint
fi

# ── 43. Shodan CLI — Internet exposure ─────────────────────
if [[ -n "$DOMAIN" ]]; then
    run_tool "shodan-cli" "shodan-cli" --profile osint
fi

# ── 44. Hydra — Brute-force (targeted) ─────────────────────
if should_run "hydra" && [[ -n "$TARGET" ]]; then
    run_tool "hydra" "hydra" --profile brute-force
fi

# ── 45. mitmproxy — Traffic interception (manual) ──────────
if should_run "mitmproxy"; then
    run_tool "mitmproxy" "mitmproxy" --profile proxy
fi

# ── 36. Report Merge ────────────────────────────────────────
header "Report Generation"
log "Merging reports..."
if [[ -f scripts/merge-reports.py ]]; then
    python3 scripts/merge-reports.py --scan-date "$SCAN_DATE" \
        --output "reports/unified-report-${SCAN_DATE}.json" 2>&1 || \
        warn "Report merge failed (non-critical)"
fi

if [[ -f scripts/cwe-summary.py ]]; then
    python3 scripts/cwe-summary.py --scan-date "$SCAN_DATE" 2>&1 || \
        warn "CWE summary failed (non-critical)"
fi

# ── 18. DefectDojo Import ───────────────────────────────────
if $DEFECTDOJO; then
    header "DefectDojo"
    log "Starting DefectDojo..."
    docker compose --profile defectdojo up -d
    info "Waiting for DefectDojo to be ready..."
    sleep 30
    if [[ -f scripts/defectdojo-import.sh ]]; then
        bash scripts/defectdojo-import.sh "$SCAN_DATE"
    fi
fi

# ── Summary ─────────────────────────────────────────────────
header "Scan Summary"
echo ""
info "Scan ID:    $SCAN_DATE"
info "Target:     ${TARGET:-N/A}"
info "Domain:     ${DOMAIN:-N/A}"
info "Reports:    $(pwd)/reports/"
echo ""

if [[ ${#RESULTS[@]} -gt 0 ]]; then
    log "Successful: ${RESULTS[*]}"
fi
if [[ ${#FAILED[@]} -gt 0 ]]; then
    warn "With issues: ${FAILED[*]}"
fi

echo ""
log "Scan completed at $(date)"
info "View unified report: cat reports/unified-report-${SCAN_DATE}.json"
info "View CWE summary:    cat reports/cwe-summary-${SCAN_DATE}.txt"
echo ""
