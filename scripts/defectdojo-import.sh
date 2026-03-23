#!/usr/bin/env bash
# ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
# Import scan results into DefectDojo
# Usage: ./scripts/defectdojo-import.sh [scan_date]

set -euo pipefail

SCAN_DATE="${1:-latest}"
DD_URL="${DD_URL:-http://localhost:8443}"
DD_API_KEY="${DD_API_KEY:-}"
DD_PRODUCT="${DD_PRODUCT:-Bug Bounty Target}"
DD_ENGAGEMENT="${DD_ENGAGEMENT:-Automated Scan}"

if [[ -z "$DD_API_KEY" ]]; then
    echo "[!] DD_API_KEY not set. Get it from DefectDojo > API v2 > Tokens"
    echo "    export DD_API_KEY=your-api-key"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORTS_DIR="$SCRIPT_DIR/../reports"

import_report() {
    local scan_type="$1"
    local file="$2"
    local tool_name="$3"

    if [[ ! -f "$file" ]]; then
        echo "  [-] $tool_name: no report found"
        return 0
    fi

    echo "  [+] Importing $tool_name..."
    curl -s -X POST "${DD_URL}/api/v2/import-scan/" \
        -H "Authorization: Token ${DD_API_KEY}" \
        -F "scan_type=${scan_type}" \
        -F "file=@${file}" \
        -F "product_name=${DD_PRODUCT}" \
        -F "engagement_name=${DD_ENGAGEMENT}" \
        -F "active=true" \
        -F "verified=false" \
        -F "close_old_findings=false" \
        -o /dev/null -w "HTTP %{http_code}\n"
}

echo "Importing reports into DefectDojo..."
echo "  URL: $DD_URL"
echo "  Product: $DD_PRODUCT"
echo ""

# Import each tool's report
import_report "Nuclei Scan" \
    "$(ls -t "$REPORTS_DIR"/nuclei/*.json 2>/dev/null | head -1)" "Nuclei"

import_report "ZAP Scan" \
    "$(ls -t "$REPORTS_DIR"/zap/*.json 2>/dev/null | head -1)" "ZAP"

import_report "SQLMap Scan" \
    "$(ls -t "$REPORTS_DIR"/sqlmap/*.json 2>/dev/null | head -1)" "SQLMap"

import_report "Semgrep JSON Report" \
    "$(ls -t "$REPORTS_DIR"/semgrep/*.json 2>/dev/null | head -1)" "Semgrep"

import_report "Gitleaks Scan" \
    "$(ls -t "$REPORTS_DIR"/gitleaks/*.json 2>/dev/null | head -1)" "Gitleaks"

import_report "Trufflehog Scan" \
    "$(ls -t "$REPORTS_DIR"/trufflehog/*.json 2>/dev/null | head -1)" "TruffleHog"

import_report "Trivy Scan" \
    "$(ls -t "$REPORTS_DIR"/trivy/*.json 2>/dev/null | head -1)" "Trivy"

import_report "CWE Checker" \
    "$(ls -t "$REPORTS_DIR"/cwe-checker/*.json 2>/dev/null | head -1)" "cwe_checker"

echo ""
echo "Done! View results at: ${DD_URL}"
