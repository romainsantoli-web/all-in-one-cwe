#!/usr/bin/env bash
# ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
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
    echo "║        Covering 95+ CWEs across 15 tools                   ║"
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
mkdir -p reports/{nuclei,zap,sqlmap,semgrep,gitleaks,trufflehog,trivy,cwe-checker,cve-bin-tool,garak,dnsreaper,subdominator,dependency-check,sstimap}

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
    local extra_args=("$@")

    if ! should_run "$name"; then
        info "Skipping $name (filtered)"
        return 0
    fi

    header "$name"
    log "Starting $name..."

    if docker compose run --rm "${extra_args[@]}" "$service" 2>&1; then
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

# ── 8. Report Merge ─────────────────────────────────────────
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

# ── 9. DefectDojo Import ────────────────────────────────────
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
