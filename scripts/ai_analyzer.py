#!/usr/bin/env python3
"""AI-powered finding analyzer — Claude/GPT explanation + PoC + remediation.

Modes:
- Online: Uses Claude or GPT API for detailed analysis
- Offline: Static templates per CWE (no API key needed)

Usage:
    python scripts/ai_analyzer.py [--input reports/scored-report.json] [--output reports/analyzed-report.json]
    python scripts/ai_analyzer.py --offline  # No LLM, template-only

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

REPORTS_DIR = Path(__file__).parent.parent / "reports"

# ---------------------------------------------------------------------------
# Offline templates: CWE → human explanation + impact + remediation
# ---------------------------------------------------------------------------
CWE_TEMPLATES: dict[str, dict] = {
    "CWE-79": {
        "explanation": "Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into web pages viewed by other users.",
        "impact": "Session hijacking, credential theft, defacement, phishing via reflected or stored payloads.",
        "remediation": "Encode all user inputs in HTML context. Use Content-Security-Policy headers. Sanitize with a whitelist approach (e.g., DOMPurify).",
        "poc_hint": "curl -s '{url}?q=<script>alert(1)</script>' | grep '<script>alert'",
    },
    "CWE-89": {
        "explanation": "SQL Injection allows attackers to manipulate database queries by injecting SQL code through user inputs.",
        "impact": "Full database compromise, data exfiltration, authentication bypass, potential RCE via stacked queries.",
        "remediation": "Use parameterized queries / prepared statements. Never concatenate user input into SQL strings. Apply least-privilege DB accounts.",
        "poc_hint": "sqlmap -u '{url}' --batch --level=3 --risk=2",
    },
    "CWE-918": {
        "explanation": "Server-Side Request Forgery (SSRF) allows an attacker to make the server send requests to unintended locations.",
        "impact": "Access to internal services, cloud metadata extraction (169.254.169.254), port scanning of internal network.",
        "remediation": "Validate and whitelist URLs server-side. Block requests to internal/private IP ranges. Use network segmentation.",
        "poc_hint": "curl '{url}?url=http://169.254.169.254/latest/meta-data/'",
    },
    "CWE-22": {
        "explanation": "Path Traversal allows reading arbitrary files on the server by manipulating file path parameters.",
        "impact": "Read sensitive files (/etc/passwd, application configs, source code), potential data breach.",
        "remediation": "Validate file paths against a whitelist. Use path canonicalization. Never expose raw file system paths.",
        "poc_hint": "curl '{url}?file=../../../etc/passwd'",
    },
    "CWE-287": {
        "explanation": "Improper Authentication allows bypassing login mechanisms or impersonating other users.",
        "impact": "Account takeover, unauthorized access to admin panels, privilege escalation.",
        "remediation": "Implement proper session management. Use MFA. Validate authentication tokens server-side.",
        "poc_hint": "Modify Authorization header or session cookie to test bypass",
    },
    "CWE-352": {
        "explanation": "Cross-Site Request Forgery (CSRF) forces authenticated users to perform unintended actions.",
        "impact": "Unauthorized state changes (password change, fund transfer, settings modification) on behalf of victim.",
        "remediation": "Implement anti-CSRF tokens. Use SameSite cookie attribute. Verify Origin/Referer headers.",
        "poc_hint": "<form action='{url}' method='POST'><input type='hidden' name='email' value='attacker@evil.com'></form>",
    },
    "CWE-502": {
        "explanation": "Deserialization of untrusted data can lead to remote code execution.",
        "impact": "Remote code execution, denial of service, complete server compromise.",
        "remediation": "Never deserialize untrusted data. Use safe serialization formats (JSON). Implement integrity checks.",
        "poc_hint": "Send crafted serialized payload to endpoint accepting serialized objects",
    },
    "CWE-601": {
        "explanation": "Open Redirect allows redirecting users to malicious sites through URL parameters.",
        "impact": "Phishing attacks, credential theft, OAuth token theft, reputation damage.",
        "remediation": "Validate redirect URLs against a whitelist of allowed domains. Use relative URLs only.",
        "poc_hint": "curl -v '{url}?redirect=https://evil.com' — check Location header",
    },
    "CWE-639": {
        "explanation": "Insecure Direct Object Reference (IDOR) allows accessing other users' data by modifying identifiers.",
        "impact": "Unauthorized data access, PII leakage, horizontal privilege escalation.",
        "remediation": "Implement proper authorization checks. Use indirect references (UUIDs). Verify object ownership server-side.",
        "poc_hint": "Change ID parameter: {url}?user_id=2 → {url}?user_id=1",
    },
    "CWE-798": {
        "explanation": "Hardcoded credentials in source code or configuration files.",
        "impact": "Account compromise, API abuse, lateral movement using exposed credentials.",
        "remediation": "Use environment variables or secrets managers (Vault, AWS Secrets Manager). Rotate exposed credentials immediately.",
        "poc_hint": "Grep source/JS files for API keys, passwords, tokens",
    },
    "CWE-312": {
        "explanation": "Sensitive data stored in cleartext, accessible to unauthorized users.",
        "impact": "Credential theft, PII exposure, compliance violations (GDPR, PCI-DSS).",
        "remediation": "Encrypt sensitive data at rest. Use proper key management. Audit storage locations.",
        "poc_hint": "Check response bodies, JS files, and localStorage for cleartext secrets",
    },
    "CWE-444": {
        "explanation": "HTTP Request Smuggling exploits discrepancies between front-end and back-end HTTP parsing.",
        "impact": "Cache poisoning, request hijacking, credential theft, WAF bypass.",
        "remediation": "Normalize HTTP parsing between proxies and backends. Use HTTP/2 end-to-end. Reject ambiguous requests.",
        "poc_hint": "Send CL.TE or TE.CL payload to test parsing discrepancy",
    },
    "CWE-1336": {
        "explanation": "Server-Side Template Injection (SSTI) allows executing arbitrary code through template engines.",
        "impact": "Remote code execution, server compromise, data exfiltration.",
        "remediation": "Never pass user input directly to template engines. Use sandboxed template execution.",
        "poc_hint": "curl '{url}?name={{{{7*7}}}}' — check if response contains '49'",
    },
}

# Default template for unknown CWEs
DEFAULT_TEMPLATE = {
    "explanation": "Vulnerability detected by automated scanning. Review the finding details for specifics.",
    "impact": "Severity-dependent impact. Review CVSS score and context for risk assessment.",
    "remediation": "Follow OWASP guidelines for the specific vulnerability class. Consult the tool's detailed output.",
    "poc_hint": "Review the raw finding output for reproduction steps.",
}


def analyze_offline(finding: dict) -> dict:
    """Generate analysis using static CWE templates."""
    cwe = finding.get("cwe_normalized") or finding.get("cwe") or ""
    cwe = str(cwe).upper().strip()
    template = CWE_TEMPLATES.get(cwe, DEFAULT_TEMPLATE)
    url = finding.get("url", "{url}")

    return {
        "explanation": template["explanation"],
        "impact": template["impact"],
        "remediation": template["remediation"],
        "poc_suggestion": template["poc_hint"].format(url=url),
        "analysis_mode": "offline",
    }


def analyze_with_llm(finding: dict, provider: str = "anthropic") -> dict:
    """Generate analysis using Claude or GPT API."""
    prompt = (
        f"Analyze this security finding for a bug bounty report:\n"
        f"- Tool: {finding.get('tool', 'unknown')}\n"
        f"- CWE: {finding.get('cwe_normalized', 'N/A')}\n"
        f"- Severity: {finding.get('severity', 'unknown')}\n"
        f"- URL: {finding.get('url', 'N/A')}\n"
        f"- Name: {finding.get('name', finding.get('id', 'N/A'))}\n"
        f"- CVSS: {finding.get('cvss_score', 'N/A')}\n\n"
        f"Provide:\n"
        f"1. A clear explanation of the vulnerability\n"
        f"2. Business impact assessment\n"
        f"3. A concrete PoC (curl command or steps)\n"
        f"4. Specific remediation steps\n\n"
        f"Format as JSON with keys: explanation, impact, poc_suggestion, remediation"
    )

    try:
        if provider == "anthropic" and os.environ.get("ANTHROPIC_API_KEY"):
            return _call_anthropic(prompt)
        elif provider == "openai" and os.environ.get("OPENAI_API_KEY"):
            return _call_openai(prompt)
    except Exception as e:
        print(f"  LLM analysis failed ({e}), falling back to offline")

    # Fallback to offline
    result = analyze_offline(finding)
    result["analysis_mode"] = "offline_fallback"
    return result


def _call_anthropic(prompt: str) -> dict:
    import requests
    resp = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": os.environ["ANTHROPIC_API_KEY"],
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json={
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 500,
            "messages": [{"role": "user", "content": prompt}],
        },
        timeout=30,
    )
    resp.raise_for_status()
    text = resp.json()["content"][0]["text"]
    try:
        parsed = json.loads(text)
        parsed["analysis_mode"] = "anthropic"
        return parsed
    except json.JSONDecodeError:
        return {
            "explanation": text,
            "impact": "",
            "poc_suggestion": "",
            "remediation": "",
            "analysis_mode": "anthropic_raw",
        }


def _call_openai(prompt: str) -> dict:
    import requests
    resp = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {os.environ['OPENAI_API_KEY']}",
            "Content-Type": "application/json",
        },
        json={
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 500,
            "response_format": {"type": "json_object"},
        },
        timeout=30,
    )
    resp.raise_for_status()
    text = resp.json()["choices"][0]["message"]["content"]
    try:
        parsed = json.loads(text)
        parsed["analysis_mode"] = "openai"
        return parsed
    except json.JSONDecodeError:
        return {
            "explanation": text,
            "impact": "",
            "poc_suggestion": "",
            "remediation": "",
            "analysis_mode": "openai_raw",
        }


def _find_latest_report() -> Path | None:
    scored = REPORTS_DIR / "scored-report.json"
    if scored.exists():
        return scored
    deduped = REPORTS_DIR / "deduped-report.json"
    if deduped.exists():
        return deduped
    candidates = sorted(REPORTS_DIR.glob("unified-report-*.json"), reverse=True)
    return candidates[0] if candidates else None


def main() -> None:
    parser = argparse.ArgumentParser(description="AI-powered finding analyzer")
    parser.add_argument("--input", "-i", help="Input report JSON")
    parser.add_argument("--output", "-o", default="reports/analyzed-report.json")
    parser.add_argument("--offline", action="store_true", help="Offline mode (no LLM API)")
    parser.add_argument("--provider", choices=["anthropic", "openai"], default="anthropic")
    parser.add_argument("--max-llm", type=int, default=10,
                        help="Max findings to analyze with LLM (cost control)")
    args = parser.parse_args()

    if args.input:
        input_path = Path(args.input)
    else:
        input_path = _find_latest_report()
        if not input_path:
            print("No report found. Run scoring_engine.py first.")
            sys.exit(1)

    data = json.loads(input_path.read_text())
    findings = data.get("findings", data) if isinstance(data, dict) else data

    use_llm = (
        not args.offline
        and (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("OPENAI_API_KEY"))
    )

    analyzed = []
    llm_count = 0
    for f in findings:
        sev = (f.get("severity") or "unknown").lower()

        # Use LLM only for critical/high findings (cost control)
        if use_llm and sev in ("critical", "high") and llm_count < args.max_llm:
            analysis = analyze_with_llm(f, args.provider)
            llm_count += 1
            print(f"  [LLM] {f.get('cwe_normalized', 'N/A')} {f.get('name', '')[:40]}")
        else:
            analysis = analyze_offline(f)

        enriched = dict(f)
        enriched["ai_analysis"] = analysis
        analyzed.append(enriched)

    output = {
        "metadata": {
            "source": str(input_path),
            "total": len(analyzed),
            "llm_analyzed": llm_count,
            "offline_analyzed": len(analyzed) - llm_count,
            "provider": args.provider if use_llm else "offline",
        },
        "findings": analyzed,
    }

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(output, indent=2, default=str))

    print(f"\nAnalyzed {len(analyzed)} findings ({llm_count} via LLM, "
          f"{len(analyzed) - llm_count} offline)")
    print(f"Output: {args.output}")


if __name__ == "__main__":
    main()
