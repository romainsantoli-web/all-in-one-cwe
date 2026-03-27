#!/usr/bin/env python3
"""Hidden Endpoint Scanner — Debug/admin/swagger/actuator probing (CWE-215/548).

Discovers hidden or unprotected endpoints:
- Debug panels (phpinfo, debug toolbar, profiler)
- Admin interfaces (wp-admin, adminer, phpmyadmin)
- API documentation (swagger, openapi, graphql playground)
- Infrastructure endpoints (actuator, metrics, healthz)
- Configuration files (.env, .git, backup files)

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import re
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from lib import (
    Finding, RateLimitedSession, get_session_from_env, log,
    parse_base_args, save_findings, load_config,
)

# ---------------------------------------------------------------------------
# Endpoint categories
# ---------------------------------------------------------------------------

ENDPOINTS: dict[str, list[dict]] = {
    "debug": [
        {"path": "/debug", "severity": "high", "cwe": "CWE-215"},
        {"path": "/debug/vars", "severity": "high", "cwe": "CWE-215"},
        {"path": "/debug/pprof", "severity": "high", "cwe": "CWE-215"},
        {"path": "/__debug__", "severity": "high", "cwe": "CWE-215"},
        {"path": "/phpinfo.php", "severity": "critical", "cwe": "CWE-215"},
        {"path": "/info.php", "severity": "high", "cwe": "CWE-215"},
        {"path": "/_profiler", "severity": "high", "cwe": "CWE-215"},
        {"path": "/_debugbar", "severity": "high", "cwe": "CWE-215"},
        {"path": "/elmah.axd", "severity": "high", "cwe": "CWE-215"},
        {"path": "/trace", "severity": "high", "cwe": "CWE-215"},
        {"path": "/server-status", "severity": "medium", "cwe": "CWE-215"},
        {"path": "/server-info", "severity": "medium", "cwe": "CWE-215"},
        {"path": "/.well-known/openid-configuration", "severity": "info", "cwe": "CWE-200"},
    ],
    "admin": [
        {"path": "/admin", "severity": "high", "cwe": "CWE-548"},
        {"path": "/admin/", "severity": "high", "cwe": "CWE-548"},
        {"path": "/administrator", "severity": "high", "cwe": "CWE-548"},
        {"path": "/wp-admin", "severity": "medium", "cwe": "CWE-548"},
        {"path": "/wp-login.php", "severity": "medium", "cwe": "CWE-548"},
        {"path": "/adminer", "severity": "critical", "cwe": "CWE-548"},
        {"path": "/adminer.php", "severity": "critical", "cwe": "CWE-548"},
        {"path": "/phpmyadmin", "severity": "critical", "cwe": "CWE-548"},
        {"path": "/pma", "severity": "critical", "cwe": "CWE-548"},
        {"path": "/panel", "severity": "medium", "cwe": "CWE-548"},
        {"path": "/console", "severity": "high", "cwe": "CWE-548"},
        {"path": "/dashboard", "severity": "medium", "cwe": "CWE-548"},
        {"path": "/manage", "severity": "medium", "cwe": "CWE-548"},
    ],
    "api_docs": [
        {"path": "/swagger", "severity": "medium", "cwe": "CWE-215"},
        {"path": "/swagger-ui", "severity": "medium", "cwe": "CWE-215"},
        {"path": "/swagger-ui.html", "severity": "medium", "cwe": "CWE-215"},
        {"path": "/swagger.json", "severity": "medium", "cwe": "CWE-215"},
        {"path": "/swagger.yaml", "severity": "medium", "cwe": "CWE-215"},
        {"path": "/api-docs", "severity": "medium", "cwe": "CWE-215"},
        {"path": "/api/docs", "severity": "medium", "cwe": "CWE-215"},
        {"path": "/openapi.json", "severity": "medium", "cwe": "CWE-215"},
        {"path": "/openapi.yaml", "severity": "medium", "cwe": "CWE-215"},
        {"path": "/v1/api-docs", "severity": "medium", "cwe": "CWE-215"},
        {"path": "/v2/api-docs", "severity": "medium", "cwe": "CWE-215"},
        {"path": "/v3/api-docs", "severity": "medium", "cwe": "CWE-215"},
        {"path": "/graphql", "severity": "medium", "cwe": "CWE-215"},
        {"path": "/graphiql", "severity": "medium", "cwe": "CWE-215"},
        {"path": "/playground", "severity": "medium", "cwe": "CWE-215"},
        {"path": "/altair", "severity": "medium", "cwe": "CWE-215"},
        {"path": "/redoc", "severity": "low", "cwe": "CWE-215"},
    ],
    "infrastructure": [
        {"path": "/actuator", "severity": "high", "cwe": "CWE-215"},
        {"path": "/actuator/env", "severity": "critical", "cwe": "CWE-215"},
        {"path": "/actuator/health", "severity": "low", "cwe": "CWE-200"},
        {"path": "/actuator/beans", "severity": "high", "cwe": "CWE-215"},
        {"path": "/actuator/configprops", "severity": "critical", "cwe": "CWE-215"},
        {"path": "/actuator/mappings", "severity": "high", "cwe": "CWE-215"},
        {"path": "/actuator/heapdump", "severity": "critical", "cwe": "CWE-215"},
        {"path": "/actuator/threaddump", "severity": "high", "cwe": "CWE-215"},
        {"path": "/metrics", "severity": "medium", "cwe": "CWE-200"},
        {"path": "/prometheus", "severity": "medium", "cwe": "CWE-200"},
        {"path": "/healthz", "severity": "info", "cwe": "CWE-200"},
        {"path": "/readyz", "severity": "info", "cwe": "CWE-200"},
        {"path": "/livez", "severity": "info", "cwe": "CWE-200"},
        {"path": "/.well-known/", "severity": "info", "cwe": "CWE-200"},
    ],
    "config_files": [
        {"path": "/.env", "severity": "critical", "cwe": "CWE-215"},
        {"path": "/.env.local", "severity": "critical", "cwe": "CWE-215"},
        {"path": "/.env.production", "severity": "critical", "cwe": "CWE-215"},
        {"path": "/.env.backup", "severity": "critical", "cwe": "CWE-215"},
        {"path": "/.git/config", "severity": "critical", "cwe": "CWE-215"},
        {"path": "/.git/HEAD", "severity": "high", "cwe": "CWE-215"},
        {"path": "/.gitignore", "severity": "low", "cwe": "CWE-200"},
        {"path": "/.svn/entries", "severity": "high", "cwe": "CWE-215"},
        {"path": "/.DS_Store", "severity": "low", "cwe": "CWE-548"},
        {"path": "/web.config", "severity": "high", "cwe": "CWE-215"},
        {"path": "/crossdomain.xml", "severity": "medium", "cwe": "CWE-200"},
        {"path": "/clientaccesspolicy.xml", "severity": "medium", "cwe": "CWE-200"},
        {"path": "/robots.txt", "severity": "info", "cwe": "CWE-200"},
        {"path": "/sitemap.xml", "severity": "info", "cwe": "CWE-200"},
        {"path": "/package.json", "severity": "medium", "cwe": "CWE-200"},
        {"path": "/composer.json", "severity": "medium", "cwe": "CWE-200"},
        {"path": "/Gemfile", "severity": "medium", "cwe": "CWE-200"},
        {"path": "/wp-config.php.bak", "severity": "critical", "cwe": "CWE-215"},
        {"path": "/config.php.bak", "severity": "critical", "cwe": "CWE-215"},
        {"path": "/backup.sql", "severity": "critical", "cwe": "CWE-215"},
        {"path": "/dump.sql", "severity": "critical", "cwe": "CWE-215"},
        {"path": "/database.sql", "severity": "critical", "cwe": "CWE-215"},
    ],
}

# Indicators that a response is a real page (not a custom 404)
FALSE_POSITIVE_PATTERNS = [
    r"page\s+not\s+found",
    r"404\s+not\s+found",
    r"does\s+not\s+exist",
    r"cannot\s+be\s+found",
    r"the\s+page\s+you",
]


def is_real_response(resp) -> bool:
    """Filter out custom 404 pages that return 200."""
    if resp.status_code in (404, 410):
        return False
    if resp.status_code in (401, 403):
        return True  # Auth-gated = endpoint exists
    if resp.status_code == 200:
        body = resp.text[:2000].lower()
        for pattern in FALSE_POSITIVE_PATTERNS:
            if re.search(pattern, body):
                return False
        return True
    if resp.status_code in (301, 302):
        return True
    return False


def scan(
    session: RateLimitedSession,
    target: str,
    categories: list[str] | None = None,
    dry_run: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []

    cats = categories or list(ENDPOINTS.keys())

    for cat in cats:
        endpoints = ENDPOINTS.get(cat, [])
        log.info("--- Scanning %s (%d paths) ---", cat, len(endpoints))

        for ep in endpoints:
            url = f"{target.rstrip('/')}{ep['path']}"
            if dry_run:
                log.info("[DRY-RUN] GET %s", url)
                continue

            try:
                resp = session.get(url, allow_redirects=False, timeout=10)
                if is_real_response(resp):
                    auth_required = resp.status_code in (401, 403)
                    findings.append(Finding(
                        title=f"Hidden Endpoint [{cat}]: {ep['path']}",
                        severity="info" if auth_required else ep["severity"],
                        cwe=ep["cwe"],
                        endpoint=url,
                        method="GET",
                        description=(
                            f"{'Protected' if auth_required else 'Unprotected'} "
                            f"{cat} endpoint found at {ep['path']}"
                        ),
                        steps=[
                            f"GET {url}",
                            f"Status: {resp.status_code}",
                            f"Content-Type: {resp.headers.get('content-type', 'unknown')}",
                        ],
                        impact=(
                            "Endpoint exists but requires authentication"
                            if auth_required
                            else f"Exposed {cat} endpoint may leak sensitive information"
                        ),
                        evidence={
                            "status": resp.status_code,
                            "content_type": resp.headers.get("content-type", ""),
                            "size": len(resp.content),
                            "auth_required": auth_required,
                        },
                        remediation=(
                            "Restrict access to non-production environments. "
                            "Remove debug/admin endpoints from production builds."
                        ),
                    ))
            except Exception as e:
                log.debug("Error scanning %s: %s", url, e)

    return findings


def main() -> None:
    parser = parse_base_args()
    parser.add_argument("--categories", nargs="*", default=None,
                        choices=list(ENDPOINTS.keys()),
                        help="Endpoint categories to scan (default: all)")
    args = parser.parse_args()

    if args.verbose:
        import logging
        logging.getLogger().setLevel(logging.DEBUG)

    session = get_session_from_env()
    if args.rate_limit:
        session.min_interval = 1.0 / args.rate_limit

    log.info("=== Hidden Endpoint Scanner starting on %s ===", args.target)
    all_findings = scan(session, args.target, args.categories, args.dry_run)
    log.info("=== Hidden Endpoint Scanner complete: %d findings ===", len(all_findings))
    save_findings(all_findings, "hidden-endpoints")


if __name__ == "__main__":
    main()
