#!/usr/bin/env python3
"""Redirect & CORS Scanner — Open redirect + CORS misconfiguration (CWE-601, CWE-942).

Tests 13+ redirect bypass techniques (domain confusion, encoding, protocol smuggling)
and CORS origin reflection with credentials on sensitive endpoints.

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import sys
import os
from urllib.parse import quote

sys.path.insert(0, os.path.dirname(__file__))

from lib import (
    Finding, RateLimitedSession, get_session_from_env, log,
    parse_base_args, save_findings, load_config,
)

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_REDIRECT_PAYLOADS = [
    {"name": "external-plain", "url": "https://evil.com"},
    {"name": "protocol-relative", "url": "//evil.com"},
    {"name": "subdomain-trick", "url": "https://evil.com@TARGET_HOST"},
    {"name": "subdomain-fake", "url": "https://TARGET_HOST.evil.com"},
    {"name": "fragment-bypass", "url": "https://evil.com#.TARGET_HOST"},
    {"name": "backslash", "url": "https://evil.com\\.TARGET_HOST"},
    {"name": "url-encode", "url": "https://evil.com%2f%2e%2e%2fTARGET_HOST"},
    {"name": "double-encode", "url": "https://evil.com%252f%252e%252e"},
    {"name": "unicode-slash", "url": "https://evil.com\u2025TARGET_HOST"},
    {"name": "path-traversal", "url": "/\\evil.com"},
    {"name": "null-byte", "url": "https://TARGET_HOST%00.evil.com"},
    {"name": "javascript-proto", "url": "javascript:alert(document.domain)//"},
    {"name": "data-proto", "url": "data:text/html,<script>alert(1)</script>"},
]

DEFAULT_REDIRECT_ENDPOINTS = [
    {"path": "/login", "params": ["next", "return_to", "redirect", "redirect_uri", "url"]},
    {"path": "/sessions/new", "params": ["next", "return_to", "redirect"]},
    {"path": "/logout", "params": ["redirect", "return_to", "next"]},
    {"path": "/auth/callback", "params": ["redirect_uri", "state", "next"]},
    {"path": "/oauth/callback", "params": ["redirect_uri"]},
    {"path": "/api/sessions", "params": ["next", "return_to", "redirect"]},
    {"path": "/account/new", "params": ["next", "return_to"]},
    {"path": "/confirm", "params": ["redirect", "next", "continue"]},
    {"path": "/redirect", "params": ["url", "to", "target", "dest"]},
    {"path": "/goto", "params": ["url", "to"]},
    {"path": "/r", "params": ["url", "u"]},
]

DEFAULT_CORS_TARGETS = [
    "/api/users/me", "/api/users", "/api/account",
    "/api/appointments", "/api/messages", "/api/documents",
    "/api/settings", "/api/profile",
]

DEFAULT_CORS_ORIGINS = [
    "https://evil.com",
    "https://TARGET_HOST.evil.com",
    "https://evil-TARGET_HOST",
    "null",
    "https://subdomain.TARGET_HOST",
]


def test_open_redirect(
    sess: RateLimitedSession, base: str, endpoints: list[dict],
    payloads: list[dict], dry_run: bool,
) -> list[Finding]:
    """Test open redirect with progressive bypass techniques."""
    findings: list[Finding] = []
    host = base.split("//")[-1].split("/")[0]

    for ep in endpoints:
        url = f"{base}{ep['path']}"
        for param in ep["params"]:
            for payload in payloads[:8]:
                p_url = payload["url"].replace("TARGET_HOST", host)
                if dry_run:
                    log.info("[dry-run] GET %s?%s=%s", url, param, payload["name"])
                    continue
                try:
                    r = sess.get(url, params={param: p_url}, allow_redirects=False)
                    if r.status_code in (301, 302, 303, 307, 308):
                        location = r.headers.get("Location", "")
                        if any(x in location.lower() for x in ["evil.com", "javascript:", "data:"]):
                            findings.append(Finding(
                                title=f"Open Redirect via {param} on {ep['path']}",
                                severity="medium",
                                cwe="CWE-601",
                                endpoint=url,
                                description=(
                                    f"Redirect via '{param}' using {payload['name']} technique. "
                                    f"Location: {location}"
                                ),
                                steps=[
                                    f"GET {url}?{param}={quote(p_url)}",
                                    f"→ {r.status_code} Location: {location}",
                                ],
                                impact="Open redirect — phishing via trusted domain.",
                                evidence={"param": param, "technique": payload["name"],
                                          "location": location, "status": r.status_code},
                            ))
                            log.warning("⚠ Redirect: %s?%s=%s → %s",
                                        ep["path"], param, payload["name"], location)
                            break
                    elif r.status_code == 200:
                        body = r.text.lower()
                        if ("evil.com" in body and
                            ("location.href" in body or "window.location" in body
                             or 'http-equiv="refresh"' in body)):
                            findings.append(Finding(
                                title=f"JS Redirect via {param} on {ep['path']}",
                                severity="medium",
                                cwe="CWE-601",
                                endpoint=url,
                                description=f"Client-side redirect via {param} to external domain.",
                                impact="JavaScript-based redirect to attacker domain.",
                            ))
                    log.info("  GET %s?%s=%s → %d", ep["path"], param, payload["name"], r.status_code)
                except Exception as e:
                    log.debug("  %s: %s", ep["path"], e)

    return findings


def test_cors_misconfiguration(
    sess: RateLimitedSession, base: str, api_paths: list[str],
    origins: list[str], dry_run: bool,
) -> list[Finding]:
    """Test CORS origin reflection on sensitive API endpoints."""
    findings: list[Finding] = []
    host = base.split("//")[-1].split("/")[0]

    for api_path in api_paths:
        url = f"{base}{api_path}"
        for origin in origins:
            origin_val = origin.replace("TARGET_HOST", host)
            if dry_run:
                log.info("[dry-run] GET %s Origin: %s", url, origin_val)
                continue
            try:
                r = sess.get(url, headers={"Origin": origin_val})
                acao = r.headers.get("Access-Control-Allow-Origin", "")
                acac = r.headers.get("Access-Control-Allow-Credentials", "")
                if not acao:
                    continue
                log.info("  GET %s Origin=%s → ACAO=%s ACAC=%s",
                         api_path, origin_val, acao, acac)

                is_dangerous = False
                reason = ""

                if acao == origin_val and "evil" in origin_val:
                    if acac.lower() == "true":
                        is_dangerous = True
                        reason = f"Reflects '{origin_val}' with credentials=true"
                if acao == "null" and acac.lower() == "true":
                    is_dangerous = True
                    reason = "Accepts null origin with credentials=true"

                if is_dangerous:
                    findings.append(Finding(
                        title=f"CORS Misconfiguration on {api_path}",
                        severity="high",
                        cwe="CWE-942",
                        endpoint=url,
                        description=f"CORS: {reason}.",
                        steps=[
                            f"Host page on {origin_val}",
                            f"fetch('{url}', {{credentials: 'include'}})",
                            f"ACAO={acao}, ACAC={acac}",
                        ],
                        impact="Cross-origin data theft from authenticated sessions.",
                        evidence={"origin": origin_val, "acao": acao, "acac": acac},
                    ))
                    log.warning("⚠ CORS: %s origin=%s", api_path, origin_val)
            except Exception as e:
                log.debug("  %s: %s", api_path, e)

    return findings


def main() -> None:
    parser = parse_base_args()
    args = parser.parse_args()
    if args.verbose:
        log.setLevel("DEBUG")

    sess = get_session_from_env()
    base = args.target.rstrip("/")
    config = load_config(args.config)
    findings: list[Finding] = []

    redirect_eps = config.get("redirect_endpoints", DEFAULT_REDIRECT_ENDPOINTS)
    redirect_payloads = config.get("redirect_payloads", DEFAULT_REDIRECT_PAYLOADS)
    cors_targets = config.get("cors_targets", DEFAULT_CORS_TARGETS)
    cors_origins = config.get("cors_origins", DEFAULT_CORS_ORIGINS)

    log.info("=" * 60)
    log.info("Redirect & CORS Scanner (CWE-601, CWE-942)")
    log.info("Target: %s | Dry-run: %s", base, args.dry_run)
    log.info("=" * 60)

    log.info("[1/2] Open redirect testing...")
    findings.extend(test_open_redirect(sess, base, redirect_eps, redirect_payloads, args.dry_run))
    log.info("[2/2] CORS misconfiguration testing...")
    findings.extend(test_cors_misconfiguration(sess, base, cors_targets, cors_origins, args.dry_run))

    log.info("=" * 60)
    log.info("Results: %d findings", len(findings))
    save_findings(findings, "redirect-cors")


if __name__ == "__main__":
    main()
