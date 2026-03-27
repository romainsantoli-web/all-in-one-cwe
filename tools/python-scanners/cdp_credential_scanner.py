#!/usr/bin/env python3
"""CDP Credential Scanner — Extract secrets from JS bundles & Nuxt state (CWE-798/321).

Uses Chrome DevTools Protocol to:
- Scan loaded JavaScript bundles for hardcoded API keys/secrets
- Extract credentials from window.__NUXT__, __NEXT_DATA__, etc.
- Find client_id/client_secret pairs in application state
- Detect exposed Firebase/GCP/AWS/Stripe keys in DOM

Requires: Chrome/Chromium with --remote-debugging-port=9222

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import json
import re
import sys
import os
import base64

sys.path.insert(0, os.path.dirname(__file__))

from lib import (
    Finding, RateLimitedSession, get_session_from_env, log,
    parse_base_args, save_findings,
)
from cdp_bridge import cdp_connect, cdp_send, cdp_eval, cdp_close

# ---------------------------------------------------------------------------
# Credential patterns (provider-agnostic)
# ---------------------------------------------------------------------------

CREDENTIAL_PATTERNS: list[dict] = [
    {"name": "AWS Access Key", "regex": r"AKIA[0-9A-Z]{16}", "severity": "critical", "cwe": "CWE-798"},
    {"name": "AWS Secret Key", "regex": r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]", "severity": "critical", "cwe": "CWE-798"},
    {"name": "GCP API Key", "regex": r"AIza[0-9A-Za-z\-_]{35}", "severity": "high", "cwe": "CWE-798"},
    {"name": "Firebase Key", "regex": r"(?i)firebase.{0,30}['\"][A-Za-z0-9\-_]{20,}['\"]", "severity": "high", "cwe": "CWE-798"},
    {"name": "Stripe Secret", "regex": r"sk_live_[0-9a-zA-Z]{24,}", "severity": "critical", "cwe": "CWE-798"},
    {"name": "Stripe Publishable", "regex": r"pk_live_[0-9a-zA-Z]{24,}", "severity": "medium", "cwe": "CWE-798"},
    {"name": "Algolia API Key", "regex": r"(?i)algolia.{0,20}(?:api|search).?key.{0,10}['\"][0-9a-f]{32}['\"]", "severity": "high", "cwe": "CWE-798"},
    {"name": "Mulesoft Credential", "regex": r"(?i)mulesoft.{0,30}(?:secret|client).{0,20}['\"][A-Za-z0-9\-_]{16,}['\"]", "severity": "critical", "cwe": "CWE-798"},
    {"name": "Private Key", "regex": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", "severity": "critical", "cwe": "CWE-321"},
    {"name": "JWT Secret", "regex": r"(?i)jwt.{0,10}secret.{0,10}['\"][^\s'\"]{8,}['\"]", "severity": "critical", "cwe": "CWE-321"},
    {"name": "Generic API Key", "regex": r"(?i)(?:api|auth|access)[_-]?(?:key|token|secret)\s*[:=]\s*['\"][A-Za-z0-9\-_]{16,}['\"]", "severity": "high", "cwe": "CWE-798"},
    {"name": "Database URL", "regex": r"(?:postgres|mysql|mongodb|redis)://[^\s'\"]{10,}", "severity": "critical", "cwe": "CWE-798"},
    {"name": "Slack Token", "regex": r"xox[bpors]-[0-9a-zA-Z\-]{10,}", "severity": "high", "cwe": "CWE-798"},
    {"name": "GitHub Token", "regex": r"gh[ps]_[A-Za-z0-9_]{36,}", "severity": "critical", "cwe": "CWE-798"},
    {"name": "SendGrid Key", "regex": r"SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{43,}", "severity": "high", "cwe": "CWE-798"},
]

# Known false positive patterns
FALSE_POSITIVES = {"placeholder", "example", "test_key", "CHANGE_ME", "your_key_here", "xxx", "000"}

# JS state containers to inspect
STATE_CONTAINERS = [
    "window.__NUXT__",
    "window.__NEXT_DATA__",
    "window.__INITIAL_STATE__",
    "window.__APP_INITIAL_STATE__",
    "window.__PRELOADED_STATE__",
    "window.__APOLLO_STATE__",
    "window.__RELAY_STORE__",
]


def _is_false_positive(value: str) -> bool:
    v = value.lower().strip("'\" ")
    return any(fp in v for fp in FALSE_POSITIVES) or len(v) < 8


def scan_js_bundles(session: CDPSession, findings: list[Finding], target: str) -> None:
    """Scan all loaded JS bundles for credential patterns."""
    # Get all loaded scripts
    result = cdp_send(session, "Debugger.enable", {})
    scripts_result = cdp_send(session, "Runtime.evaluate", {
        "expression": """
        (function() {
            var scripts = document.querySelectorAll('script[src]');
            return Array.from(scripts).map(s => s.src).filter(s => s.endsWith('.js'));
        })()
        """,
        "returnByValue": True,
    })

    script_urls = []
    if scripts_result and "result" in scripts_result:
        val = scripts_result["result"].get("value", [])
        if isinstance(val, list):
            script_urls = val

    log.info("Found %d JS bundles to scan", len(script_urls))

    for url in script_urls[:50]:  # Cap at 50 bundles
        try:
            resp = cdp_send(session, "Runtime.evaluate", {
                "expression": f"""
                (async function() {{
                    var r = await fetch("{url}");
                    return await r.text();
                }})()
                """,
                "awaitPromise": True,
                "returnByValue": True,
            })
            if not resp or "result" not in resp:
                continue
            content = resp["result"].get("value", "")
            if not isinstance(content, str) or len(content) < 100:
                continue

            _scan_text(content, url, findings, target)

        except Exception as e:
            log.debug("Error fetching bundle %s: %s", url, e)


def _scan_text(content: str, source: str, findings: list[Finding], target: str) -> None:
    """Scan text content for credential patterns."""
    for pattern in CREDENTIAL_PATTERNS:
        for match in re.finditer(pattern["regex"], content):
            matched_value = match.group(0)
            if _is_false_positive(matched_value):
                continue
            # Extract context (±60 chars)
            start = max(0, match.start() - 60)
            end = min(len(content), match.end() + 60)
            context = content[start:end].replace("\n", " ").strip()

            findings.append(Finding(
                title=f"{pattern['name']} found in JS bundle",
                severity=pattern["severity"],
                cwe=pattern["cwe"],
                endpoint=source,
                method="GET",
                description=(
                    f"Hardcoded {pattern['name']} detected in JavaScript bundle. "
                    "Client-side credentials can be extracted by any visitor."
                ),
                evidence={"context": context, "pattern": pattern["name"]},
                remediation=(
                    "Move secrets to server-side environment variables. "
                    "Use backend proxy for API calls requiring credentials. "
                    "Rotate any exposed keys immediately."
                ),
            ))


def scan_state_containers(session: CDPSession, findings: list[Finding], target: str) -> None:
    """Extract credentials from JS framework state containers."""
    for container in STATE_CONTAINERS:
        try:
            result = cdp_send(session, "Runtime.evaluate", {
                "expression": f"JSON.stringify({container})",
                "returnByValue": True,
            })
            if not result or "result" not in result:
                continue
            value = result["result"].get("value")
            if not value or value == "undefined" or value == "null":
                continue

            log.info("Found state container: %s", container)
            _scan_text(value, f"{target} ({container})", findings, target)

            # Also search for common credential field names
            try:
                state = json.loads(value)
                _deep_search_keys(state, container, findings, target)
            except (json.JSONDecodeError, TypeError):
                pass

        except Exception as e:
            log.debug("Error inspecting %s: %s", container, e)


def _deep_search_keys(
    obj: Any, path: str, findings: list[Finding], target: str, depth: int = 0
) -> None:
    """Recursively search JSON object for credential-like keys."""
    if depth > 10:
        return
    SENSITIVE_KEYS = {
        "secret", "password", "apikey", "api_key", "apiKey",
        "client_secret", "clientSecret", "private_key", "privateKey",
        "access_token", "accessToken", "refresh_token", "refreshToken",
    }
    if isinstance(obj, dict):
        for key, value in obj.items():
            key_lower = key.lower().replace("-", "_")
            if any(s in key_lower for s in SENSITIVE_KEYS) and isinstance(value, str):
                if not _is_false_positive(value):
                    findings.append(Finding(
                        title=f"Credential in client state: {key}",
                        severity="critical" if "secret" in key_lower or "password" in key_lower else "high",
                        cwe="CWE-798",
                        endpoint=f"{target} ({path}.{key})",
                        description=(
                            f"Sensitive credential field '{key}' exposed in client-side "
                            f"state container {path}. Value is accessible to any page visitor."
                        ),
                        evidence={"key": key, "container": path, "value_length": len(value)},
                        remediation="Remove credentials from client-side state. Use server-side API proxying.",
                    ))
            if isinstance(value, (dict, list)):
                _deep_search_keys(value, f"{path}.{key}", findings, target, depth + 1)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            if isinstance(item, (dict, list)):
                _deep_search_keys(item, f"{path}[{i}]", findings, target, depth + 1)


# ---------------------------------------------------------------------------
# Inline script scanning
# ---------------------------------------------------------------------------

def scan_inline_scripts(session: CDPSession, findings: list[Finding], target: str) -> None:
    """Scan inline <script> tags for credentials."""
    result = cdp_send(session, "Runtime.evaluate", {
        "expression": """
        (function() {
            var scripts = document.querySelectorAll('script:not([src])');
            return Array.from(scripts).map(s => s.textContent).join('\\n---SCRIPT_SEP---\\n');
        })()
        """,
        "returnByValue": True,
    })
    if not result or "result" not in result:
        return
    content = result["result"].get("value", "")
    if content:
        _scan_text(content, f"{target} (inline scripts)", findings, target)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = parse_base_args()
    parser.add_argument("--cdp-url", default=os.environ.get("CDP_URL", "http://localhost:9222"),
                        help="Chrome DevTools debug URL")
    parser.add_argument("--navigate", action="store_true",
                        help="Navigate browser to target URL before scanning")
    args = parser.parse_args()

    target = args.target
    if not target:
        log.error("--target is required")
        sys.exit(2)

    findings: list[Finding] = []

    try:
        session = cdp_connect(url=args.cdp_url, target_url=target if args.navigate else None)

        if args.navigate:
            import time
            time.sleep(3)  # Wait for page load

        log.info("Scanning JS bundles for credentials...")
        scan_js_bundles(session, findings, target)

        log.info("Scanning state containers...")
        scan_state_containers(session, findings, target)

        log.info("Scanning inline scripts...")
        scan_inline_scripts(session, findings, target)

        cdp_close(session)

    except Exception as e:
        log.error("CDP connection failed: %s — falling back to HTTP scanning", e)
        # Fallback: HTTP-only credential scanning
        session_http = get_session_from_env()
        try:
            resp = session_http.get(target, timeout=15)
            _scan_text(resp.text, target, findings, target)
        except Exception as ex:
            log.error("HTTP fallback also failed: %s", ex)

    # Deduplicate by (title, endpoint)
    seen = set()
    unique = []
    for f in findings:
        key = (f.title, f.endpoint)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    save_findings(unique, "cdp-credential-scanner")
    log.info("CDP Credential Scanner complete: %d findings", len(unique))
    sys.exit(0 if not unique else 1)


if __name__ == "__main__":
    main()
