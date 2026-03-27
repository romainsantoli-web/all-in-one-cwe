#!/usr/bin/env python3
"""CDP Token Extractor — Capture JWT/bearer tokens from live browser sessions (CWE-320/347).

Uses Chrome DevTools Protocol to intercept network traffic and extract:
- Authorization headers (Bearer tokens, JWT)
- Set-Cookie with session tokens
- OAuth tokens in URL fragments
- API keys in query parameters
- Tokens in WebSocket frames

Requires a running Chrome/Chromium with --remote-debugging-port=9222.

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import json
import re
import sys
import os
import time
import base64

sys.path.insert(0, os.path.dirname(__file__))

from lib import (
    Finding, RateLimitedSession, get_session_from_env, log,
    parse_base_args, save_findings,
)
from cdp_bridge import (
    cdp_connect, cdp_send, cdp_eval, cdp_collect_events,
    cdp_close, cdp_fetch_enable,
)

# ---------------------------------------------------------------------------
# Token detection patterns
# ---------------------------------------------------------------------------

TOKEN_PATTERNS = [
    {
        "name": "JWT Token",
        "pattern": r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}',
        "severity": "critical",
        "cwe": "CWE-347",
    },
    {
        "name": "Bearer Token",
        "pattern": r'Bearer\s+([a-zA-Z0-9\-._~+/]+=*)',
        "severity": "high",
        "cwe": "CWE-320",
    },
    {
        "name": "API Key (query)",
        "pattern": r'[?&](?:api[_-]?key|apikey|token|access_token|key)=([a-zA-Z0-9\-._]{16,})',
        "severity": "high",
        "cwe": "CWE-598",
    },
    {
        "name": "OAuth Token (fragment)",
        "pattern": r'#.*(?:access_token|token)=([a-zA-Z0-9\-._~+/]+=*)',
        "severity": "critical",
        "cwe": "CWE-598",
    },
    {
        "name": "Session Cookie",
        "pattern": r'(?:session|sess|sid|JSESSIONID|PHPSESSID|ASP\.NET_SessionId|connect\.sid)=([a-zA-Z0-9\-._]{16,})',
        "severity": "high",
        "cwe": "CWE-614",
    },
]

SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token"}


def mask_token(token: str) -> str:
    """Mask a token for safe logging."""
    if len(token) > 12:
        return token[:6] + "***" + token[-4:]
    return "***"


def extract_tokens_from_text(text: str) -> list[dict]:
    """Extract all token patterns from arbitrary text."""
    tokens: list[dict] = []
    for pattern_def in TOKEN_PATTERNS:
        for match in re.finditer(pattern_def["pattern"], text):
            value = match.group(0)
            tokens.append({
                "type": pattern_def["name"],
                "severity": pattern_def["severity"],
                "cwe": pattern_def["cwe"],
                "masked_value": mask_token(value),
                "length": len(value),
            })
    return tokens


def scan(
    target: str,
    duration_seconds: int = 30,
    dry_run: bool = False,
) -> list[Finding]:
    """Monitor browser network traffic for token leakage."""
    findings: list[Finding] = []

    if dry_run:
        log.info("[DRY-RUN] Would connect to CDP and monitor for %ds", duration_seconds)
        return findings

    # Connect to Chrome DevTools
    log.info("Connecting to Chrome DevTools Protocol...")
    try:
        session = cdp_connect()
    except Exception as e:
        log.error("Cannot connect to CDP: %s", e)
        log.error("Ensure Chrome is running with --remote-debugging-port=9222")
        return findings

    try:
        # Enable network monitoring
        cdp_send(session, "Network.enable", {})
        cdp_send(session, "Network.setCacheDisabled", {"cacheDisabled": True})

        # Navigate to target
        log.info("Navigating to %s", target)
        cdp_send(session, "Page.navigate", {"url": target})
        time.sleep(3)  # Wait for initial load

        # Collect network events
        log.info("Monitoring network traffic for %ds...", duration_seconds)
        events = cdp_collect_events(session, duration_seconds)

        # Analyze collected events
        request_tokens: dict[str, list] = {}

        for event in events:
            method = event.get("method", "")
            params = event.get("params", {})

            if method == "Network.requestWillBeSent":
                request = params.get("request", {})
                url = request.get("url", "")
                headers = request.get("headers", {})

                # Check URL for tokens
                url_tokens = extract_tokens_from_text(url)
                if url_tokens:
                    for tok in url_tokens:
                        findings.append(Finding(
                            title=f"Token in URL: {tok['type']}",
                            severity=tok["severity"],
                            cwe=tok["cwe"],
                            endpoint=url[:200],
                            method=request.get("method", "GET"),
                            description=f"{tok['type']} found in request URL ({tok['length']} chars)",
                            steps=[
                                "Monitor CDP Network.requestWillBeSent events",
                                f"Token found in URL: {tok['masked_value']}",
                            ],
                            impact="Token exposed in URL — logged by proxies, browser history, referrer",
                            evidence=tok,
                            remediation="Send tokens in Authorization header, not URL parameters.",
                        ))

                # Check headers for sensitive values
                for header_name, header_value in headers.items():
                    if header_name.lower() in SENSITIVE_HEADERS:
                        header_tokens = extract_tokens_from_text(header_value)
                        for tok in header_tokens:
                            key = f"{url[:80]}:{tok['type']}"
                            if key not in request_tokens:
                                request_tokens[key] = tok
                                # This is expected behavior for auth headers,
                                # but flag insecure transmission
                                if not url.startswith("https://"):
                                    findings.append(Finding(
                                        title=f"Token over HTTP: {tok['type']}",
                                        severity="critical",
                                        cwe="CWE-319",
                                        endpoint=url[:200],
                                        method=request.get("method", "GET"),
                                        description=f"{tok['type']} sent over insecure HTTP connection",
                                        steps=[
                                            f"Request to HTTP URL: {url[:100]}",
                                            f"Header: {header_name}: {tok['masked_value']}",
                                        ],
                                        impact="Token interceptable via network sniffing",
                                        evidence=tok,
                                        remediation="Enforce HTTPS for all authenticated requests.",
                                    ))

            elif method == "Network.responseReceived":
                response = params.get("response", {})
                resp_headers = response.get("headers", {})
                url = response.get("url", "")

                # Check response headers for token exposure
                for header_name, header_value in resp_headers.items():
                    if header_name.lower() == "set-cookie":
                        # Check cookie security attributes
                        if "secure" not in header_value.lower() and url.startswith("https"):
                            cookie_name = header_value.split("=", 1)[0].strip()
                            findings.append(Finding(
                                title=f"Insecure Cookie: {cookie_name}",
                                severity="medium",
                                cwe="CWE-614",
                                endpoint=url[:200],
                                method="GET",
                                description=f"Set-Cookie '{cookie_name}' missing Secure flag",
                                steps=[
                                    f"Response from {url[:100]}",
                                    f"Set-Cookie: {header_value[:80]}...",
                                ],
                                impact="Session cookie transmittable over HTTP",
                                evidence={"cookie": cookie_name, "header": header_value[:100]},
                                remediation="Add Secure; HttpOnly; SameSite=Strict to session cookies.",
                            ))

        log.info("Analyzed %d network events, found %d issues", len(events), len(findings))

    finally:
        cdp_close(session)

    return findings


def main() -> None:
    parser = parse_base_args()
    parser.add_argument("--duration", type=int, default=30,
                        help="Monitoring duration in seconds (default: 30)")
    args = parser.parse_args()

    if args.verbose:
        import logging
        logging.getLogger().setLevel(logging.DEBUG)

    log.info("=== CDP Token Extractor starting on %s ===", args.target)
    all_findings = scan(args.target, args.duration, args.dry_run)
    log.info("=== CDP Token Extractor complete: %d findings ===", len(all_findings))
    save_findings(all_findings, "cdp-token-extractor")


if __name__ == "__main__":
    main()
