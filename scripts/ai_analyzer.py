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

# Allow imports from parent dir (llm/ package)
sys.path.insert(0, str(Path(__file__).parent.parent))

from llm.base import LLMMessage  # noqa: E402
from llm.registry import get_provider, list_providers  # noqa: E402

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


def _auto_detect_provider() -> str | None:
    """Auto-detect best available provider from env vars."""
    # Priority: Copilot Pro (free) > Anthropic > OpenAI > Mistral > Gemini > Copilot
    if os.path.exists("/tmp/copilot_token.json") or os.environ.get("COPILOT_JWT"):
        return "copilot-pro"
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "claude"
    if os.environ.get("OPENAI_API_KEY"):
        return "gpt"
    if os.environ.get("MISTRAL_API_KEY"):
        return "mistral"
    if os.environ.get("GEMINI_API_KEY"):
        return "gemini"
    if os.environ.get("GITHUB_TOKEN"):
        return "copilot"
    return None


def analyze_with_llm(finding: dict, provider_name: str = "auto", model: str | None = None) -> dict:
    """Generate analysis using any configured LLM provider."""
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

    resolved = provider_name if provider_name != "auto" else _auto_detect_provider()
    if not resolved:
        result = analyze_offline(finding)
        result["analysis_mode"] = "offline_no_provider"
        return result

    try:
        kwargs: dict = {}
        if model:
            kwargs["model"] = model
        provider = get_provider(resolved, **kwargs)
        response = provider.simple_chat(prompt, max_tokens=500)

        try:
            parsed = json.loads(response)
            parsed["analysis_mode"] = resolved
            parsed["model"] = provider.model
            return parsed
        except json.JSONDecodeError:
            return {
                "explanation": response,
                "impact": "",
                "poc_suggestion": "",
                "remediation": "",
                "analysis_mode": f"{resolved}_raw",
                "model": provider.model,
            }
    except Exception as e:
        print(f"  LLM analysis failed ({e}), falling back to offline")

    result = analyze_offline(finding)
    result["analysis_mode"] = "offline_fallback"
    return result


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
    parser.add_argument("--provider", default="auto",
                        help=f"LLM provider: auto, {', '.join(list_providers())} (default: auto)")
    parser.add_argument("--model", default=None, help="Override model name for the provider")
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

    use_llm = not args.offline and (
        args.provider != "auto" or _auto_detect_provider() is not None
    )

    analyzed = []
    llm_count = 0
    for f in findings:
        sev = (f.get("severity") or "unknown").lower()

        # Use LLM only for critical/high findings (cost control)
        if use_llm and sev in ("critical", "high") and llm_count < args.max_llm:
            analysis = analyze_with_llm(f, args.provider, args.model)
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
