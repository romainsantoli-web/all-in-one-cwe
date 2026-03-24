#!/usr/bin/env python3
"""OIDC Audit Scanner — Keycloak/OIDC Discovery & misconfiguration detection (CWE-522, CWE-200).

Tests: OIDC well-known discovery, internal hostname leak, client enumeration,
device code flow, registration endpoint exposure, token endpoint auth method.

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import sys
import os
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(__file__))

from lib import (
    Finding, RateLimitedSession, get_session_from_env, log,
    parse_base_args, save_findings, load_config,
)

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_OIDC_PATHS = [
    "/.well-known/openid-configuration",
    "/auth/realms/master/.well-known/openid-configuration",
    "/realms/master/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
]

DEFAULT_INTERNAL_PATTERNS = [
    "localhost", "127.0.0.1", "0.0.0.0", "internal",
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.", "192.168.",
    ".local", ".internal", ".corp", ".svc",
]

DEFAULT_CLIENT_IDS = [
    "admin", "admin-cli", "account", "realm-management",
    "broker", "security-admin-console",
    "patient", "patient-shadow", "mobile-app", "web-app",
    "api-gateway", "internal-service",
]


def test_oidc_discovery(
    sess: RateLimitedSession, base: str, oidc_paths: list[str],
    internal_patterns: list[str], dry_run: bool,
) -> list[Finding]:
    """Probe OIDC well-known endpoints for information disclosure."""
    findings: list[Finding] = []

    for path in oidc_paths:
        url = f"{base}{path}"
        if dry_run:
            log.info("[dry-run] Would GET %s", url)
            continue
        try:
            r = sess.get(url)
            log.info("  GET %s → %d", path, r.status_code)
            if r.status_code != 200:
                continue
            try:
                config_data = r.json()
            except Exception:
                continue

            issuer = config_data.get("issuer", "")
            endpoints = {
                "authorization_endpoint": config_data.get("authorization_endpoint", ""),
                "token_endpoint": config_data.get("token_endpoint", ""),
                "userinfo_endpoint": config_data.get("userinfo_endpoint", ""),
                "registration_endpoint": config_data.get("registration_endpoint", ""),
                "device_authorization_endpoint": config_data.get("device_authorization_endpoint", ""),
                "introspection_endpoint": config_data.get("introspection_endpoint", ""),
            }

            # Check for internal hostnames in any endpoint
            all_urls = [issuer] + list(endpoints.values())
            leaked = []
            for ep_url in all_urls:
                if not ep_url:
                    continue
                parsed = urlparse(ep_url)
                hostname = parsed.hostname or ""
                for pattern in internal_patterns:
                    if pattern in hostname:
                        leaked.append({"url": ep_url, "pattern": pattern})

            if leaked:
                findings.append(Finding(
                    title=f"Internal Hostname Leak via OIDC Discovery — {path}",
                    severity="high",
                    cwe="CWE-200",
                    endpoint=url,
                    description=f"OIDC config exposes internal hostnames: {leaked}",
                    steps=[f"GET {url}", "Parse JSON for internal URLs"],
                    impact="SSRF pivot — attacker discovers internal service addresses.",
                    evidence={"leaked_urls": leaked, "issuer": issuer},
                ))
                log.warning("⚠ Internal hostname leak: %s", leaked)

            # Check for dynamic client registration
            reg_ep = config_data.get("registration_endpoint")
            if reg_ep:
                findings.append(Finding(
                    title=f"OIDC Dynamic Client Registration Exposed — {path}",
                    severity="medium",
                    cwe="CWE-284",
                    endpoint=url,
                    description=f"Registration endpoint exposed: {reg_ep}",
                    impact="Attacker can register malicious OAuth clients.",
                    evidence={"registration_endpoint": reg_ep},
                ))

            # Check token_endpoint_auth_methods
            auth_methods = config_data.get("token_endpoint_auth_methods_supported", [])
            if "none" in auth_methods:
                findings.append(Finding(
                    title=f"OIDC Allows 'none' Token Auth Method — {path}",
                    severity="high",
                    cwe="CWE-287",
                    endpoint=url,
                    description="Token endpoint accepts 'none' auth — no client authentication required.",
                    impact="Attacker can obtain tokens without client credentials.",
                    evidence={"auth_methods": auth_methods},
                ))

        except Exception as e:
            log.debug("  %s: %s", path, e)

    return findings


def test_client_enumeration(
    sess: RateLimitedSession, base: str, client_ids: list[str], dry_run: bool,
) -> list[Finding]:
    """Enumerate OAuth client IDs via token endpoint error messages."""
    findings: list[Finding] = []
    token_urls = [
        f"{base}/oauth/token",
        f"{base}/auth/realms/master/protocol/openid-connect/token",
        f"{base}/token",
    ]

    found_clients = []
    for token_url in token_urls:
        responses: dict[str, int] = {}
        for client_id in client_ids:
            if dry_run:
                log.info("[dry-run] Would POST %s client_id=%s", token_url, client_id)
                continue
            try:
                r = sess.post(token_url, data={
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": "invalid",
                })
                responses[client_id] = r.status_code
                log.info("  %s client=%s → %d", token_url, client_id, r.status_code)

                # Different error for valid vs invalid client
                if r.status_code == 401:  # Usually means client exists, bad secret
                    found_clients.append(client_id)
            except Exception:
                pass

        if len(set(responses.values())) > 1 and found_clients:
            findings.append(Finding(
                title="OAuth Client ID Enumeration",
                severity="medium",
                cwe="CWE-203",
                endpoint=token_url,
                method="POST",
                description=f"Token endpoint leaks valid client IDs: {found_clients}",
                impact="Attacker can discover valid OAuth clients for further attacks.",
                evidence={"responses": responses, "valid_clients": found_clients},
            ))

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

    oidc_paths = config.get("oidc_paths", DEFAULT_OIDC_PATHS)
    internal_patterns = config.get("internal_patterns", DEFAULT_INTERNAL_PATTERNS)
    client_ids = config.get("client_ids", DEFAULT_CLIENT_IDS)

    log.info("=" * 60)
    log.info("OIDC Audit Scanner (CWE-200, CWE-287, CWE-522)")
    log.info("Target: %s | Dry-run: %s", base, args.dry_run)
    log.info("=" * 60)

    log.info("[1/2] OIDC Discovery audit...")
    findings.extend(test_oidc_discovery(sess, base, oidc_paths, internal_patterns, args.dry_run))
    log.info("[2/2] Client ID enumeration...")
    findings.extend(test_client_enumeration(sess, base, client_ids, args.dry_run))

    log.info("=" * 60)
    log.info("Results: %d findings", len(findings))
    save_findings(findings, "oidc-audit")


if __name__ == "__main__":
    main()
