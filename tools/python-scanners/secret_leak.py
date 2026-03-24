#!/usr/bin/env python3
"""Secret Leak Scanner — CWE-312, CWE-540, CWE-615 (Exposed Secrets).

Comprehensive secret/token leakage detection combining:
  1. HTTP response body scanning for hardcoded secrets (API keys, tokens, passwords)
  2. JavaScript file scanning for leaked credentials
  3. Source map analysis for full source disclosure
  4. Inline config mining for exposed keys (window.*, env vars)
  5. Common secret-bearing endpoint probing (/env, /debug, /config, etc.)

Source: db_deep_probe.js (API key discovery) + db_phase14b_apidiscovery.js
        (JS bundle secrets) from Doctolib bug bounty campaign — both found
        exposed API keys on production.

Usage:
    python secret_leak.py --target https://example.com --dry-run
    python secret_leak.py --target https://example.com --config /configs/secret-leak-config.yaml

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import re
import sys
from urllib.parse import urljoin, urlparse

from lib import (
    Finding,
    RateLimitedSession,
    get_session_from_env,
    load_config,
    log,
    parse_base_args,
    save_findings,
)

TOOL_NAME = "secret-leak"

# ---------------------------------------------------------------------------
# Secret patterns — compiled regex with severity
# ---------------------------------------------------------------------------

SECRET_PATTERNS: list[dict] = [
    # Cloud provider keys
    {"name": "AWS Access Key", "regex": re.compile(r"""(?:^|[^A-Za-z0-9/+])(AKIA[0-9A-Z]{16})"""), "severity": "critical"},
    {"name": "AWS Secret Key", "regex": re.compile(r"""(?:aws_secret_access_key|secret_key)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?""", re.I), "severity": "critical"},
    {"name": "GCP API Key", "regex": re.compile(r"""AIza[0-9A-Za-z\-_]{35}"""), "severity": "critical"},
    {"name": "GCP Service Account", "regex": re.compile(r""""type"\s*:\s*"service_account".*?"private_key":\s*"-----BEGIN""", re.DOTALL), "severity": "critical"},

    # Payment / SaaS
    {"name": "Stripe Secret Key", "regex": re.compile(r"""sk_live_[0-9a-zA-Z]{24,}"""), "severity": "critical"},
    {"name": "Stripe Publishable Key", "regex": re.compile(r"""pk_live_[0-9a-zA-Z]{24,}"""), "severity": "medium"},
    {"name": "Stripe Restricted Key", "regex": re.compile(r"""rk_live_[0-9a-zA-Z]{24,}"""), "severity": "critical"},
    {"name": "PayPal Client Secret", "regex": re.compile(r"""(?:paypal|pp)[\w_-]*(?:secret|key)\s*[:=]\s*['"]?([A-Za-z0-9\-_]{20,})['"]?""", re.I), "severity": "high"},

    # Auth tokens
    {"name": "JWT Token", "regex": re.compile(r"""eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"""), "severity": "high"},
    {"name": "Bearer Token (hardcoded)", "regex": re.compile(r"""(?:bearer|authorization)\s*[:=]\s*['"]?Bearer\s+([A-Za-z0-9\-_./+=]{20,})['"]?""", re.I), "severity": "high"},
    {"name": "Basic Auth (hardcoded)", "regex": re.compile(r"""(?:authorization)\s*[:=]\s*['"]?Basic\s+([A-Za-z0-9+/=]{10,})['"]?""", re.I), "severity": "critical"},

    # Generic API keys
    {"name": "Generic API Key", "regex": re.compile(r"""(?:api_?key|apikey|api_?secret)\s*[:=]\s*['"]?([A-Za-z0-9\-_]{16,64})['"]?""", re.I), "severity": "high"},
    {"name": "Generic Secret", "regex": re.compile(r"""(?:secret|password|passwd|pwd)\s*[:=]\s*['"]([^'"]{8,64})['"]""", re.I), "severity": "high"},
    {"name": "Generic Token", "regex": re.compile(r"""(?:token|access_token|auth_token|session_token)\s*[:=]\s*['"]([A-Za-z0-9\-_./+=]{16,})['"]""", re.I), "severity": "high"},

    # Database
    {"name": "Database URL", "regex": re.compile(r"""(?:postgres|mysql|mongodb|redis|amqp)(?:ql)?://[^\s'"<>]{10,200}""", re.I), "severity": "critical"},
    {"name": "Connection String", "regex": re.compile(r"""(?:Server|Data Source)=[^;]+;.*(?:Password|Pwd)=[^;]+""", re.I), "severity": "critical"},

    # Communication / Messaging
    {"name": "Slack Token", "regex": re.compile(r"""xox[bpras]-[0-9]{10,13}-[0-9a-zA-Z]{10,}"""), "severity": "critical"},
    {"name": "Slack Webhook", "regex": re.compile(r"""hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{20,}"""), "severity": "high"},
    {"name": "Discord Webhook", "regex": re.compile(r"""discord(?:app)?\.com/api/webhooks/\d+/[\w-]+"""), "severity": "high"},
    {"name": "Telegram Bot Token", "regex": re.compile(r"""\d{8,10}:[A-Za-z0-9_-]{35}"""), "severity": "high"},
    {"name": "Twilio API Key", "regex": re.compile(r"""SK[0-9a-fA-F]{32}"""), "severity": "high"},

    # Source control / CI
    {"name": "GitHub Token", "regex": re.compile(r"""gh[ps]_[A-Za-z0-9_]{36,}"""), "severity": "critical"},
    {"name": "GitHub OAuth", "regex": re.compile(r"""gho_[A-Za-z0-9_]{36,}"""), "severity": "critical"},
    {"name": "GitLab Token", "regex": re.compile(r"""glpat-[\w-]{20,}"""), "severity": "critical"},
    {"name": "NPM Token", "regex": re.compile(r"""npm_[A-Za-z0-9]{36}"""), "severity": "high"},

    # Encryption / Signing
    {"name": "Private Key", "regex": re.compile(r"""-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"""), "severity": "critical"},
    {"name": "SSH Private Key", "regex": re.compile(r"""-----BEGIN OPENSSH PRIVATE KEY-----"""), "severity": "critical"},

    # Cloud infrastructure
    {"name": "Heroku API Key", "regex": re.compile(r"""heroku.*?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}""", re.I), "severity": "high"},
    {"name": "SendGrid API Key", "regex": re.compile(r"""SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{22,}"""), "severity": "critical"},
    {"name": "Mailgun API Key", "regex": re.compile(r"""key-[0-9a-zA-Z]{32}"""), "severity": "high"},

    # Anthropic / OpenAI
    {"name": "OpenAI API Key", "regex": re.compile(r"""sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}"""), "severity": "critical"},
    {"name": "Anthropic API Key", "regex": re.compile(r"""sk-ant-[A-Za-z0-9\-_]{80,}"""), "severity": "critical"},

    # Firebase / Google
    {"name": "Firebase Config", "regex": re.compile(r"""(?:firebase|firebaseConfig)\s*[:=]\s*\{[^}]*apiKey\s*:\s*['"]([^'"]+)['"]""", re.I), "severity": "high"},
    {"name": "Google OAuth Client Secret", "regex": re.compile(r"""(?:client_secret)\s*[:=]\s*['"]([A-Za-z0-9\-_]{24,})['"]""", re.I), "severity": "high"},

    # Misc
    {"name": "MapBox Token", "regex": re.compile(r"""pk\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"""), "severity": "medium"},
    {"name": "Internal IP Address", "regex": re.compile(r"""(?:^|[^0-9])((?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3})(?:[^0-9]|$)"""), "severity": "low"},
]

# False positive check: common placeholder values to ignore
FALSE_POSITIVE_VALUES = {
    "your_api_key_here", "YOUR_API_KEY", "CHANGE_ME", "xxx", "placeholder",
    "sk_test_", "pk_test_", "test_key", "example", "fake", "dummy", "TODO",
    "REPLACE_ME", "INSERT_TOKEN", "YOUR_SECRET", "your-secret-here",
}

# ---------------------------------------------------------------------------
# Secret-bearing endpoints to probe
# ---------------------------------------------------------------------------

SECRET_ENDPOINTS = [
    # Debug / config endpoints
    "/env", "/.env", "/debug", "/debug/vars", "/debug/pprof",
    "/config", "/config.json", "/config.js", "/configuration",
    "/info", "/server-info", "/server-status",
    "/actuator", "/actuator/env", "/actuator/configprops", "/actuator/health",
    # Admin panels
    "/admin", "/admin/config", "/phpinfo.php", "/elmah.axd",
    # Version control
    "/.git/config", "/.git/HEAD",
    "/.svn/entries", "/.hg/hgrc",
    # Build artifacts
    "/webpack.config.js", "/.webpack/",
    "/package.json", "/package-lock.json", "/yarn.lock",
    "/composer.json", "/Gemfile", "/requirements.txt",
    # Environment / secrets files
    "/.env", "/.env.local", "/.env.production", "/.env.staging",
    "/app/config/parameters.yml", "/wp-config.php.bak",
    # API documentation (may leak keys in examples)
    "/swagger-ui.html", "/swagger.json", "/openapi.yaml",
    "/api-docs", "/docs/api", "/redoc",
    # Health / metrics
    "/health", "/healthz", "/ready", "/metrics", "/prometheus",
    "/status", "/version", "/api/version",
]

# Paths to scan for JS files (webpack chunks, etc.)
JS_DISCOVERY_PATHS = [
    "/", "/login", "/app", "/dashboard",
]


# ---------------------------------------------------------------------------
# Phase 1: Probe secret-bearing endpoints
# ---------------------------------------------------------------------------


def phase_probe_endpoints(
    session: RateLimitedSession,
    target: str,
    endpoints: list[str],
    dry_run: bool = False,
) -> list[dict]:
    """Probe known secret-exposing endpoints and scan responses."""
    results: list[dict] = []

    for ep in endpoints:
        url = urljoin(target, ep)
        if dry_run:
            log.info("[DRY-RUN] Would probe %s", url)
            continue
        try:
            resp = session.get(url, allow_redirects=False)
            if resp.status_code >= 400:
                continue

            # Scan response body for secrets
            secrets_found = _scan_text_for_secrets(resp.text, url)
            if secrets_found:
                results.append({
                    "url": url,
                    "status": resp.status_code,
                    "content_type": resp.headers.get("Content-Type", ""),
                    "secrets": secrets_found,
                })
            elif resp.status_code == 200:
                # Even without secrets, some endpoints are sensitive
                ct = resp.headers.get("Content-Type", "").lower()
                if any(k in ep for k in (".env", ".git", "actuator", "phpinfo", "debug")):
                    results.append({
                        "url": url,
                        "status": resp.status_code,
                        "content_type": ct,
                        "secrets": [],
                        "note": "Sensitive endpoint accessible (may leak info)",
                    })

        except Exception as exc:
            log.warning("Error probing %s: %s", url, exc)

    return results


# ---------------------------------------------------------------------------
# Phase 2: Scan JS bundles for hardcoded secrets
# ---------------------------------------------------------------------------


def phase_scan_js_bundles(
    session: RateLimitedSession,
    target: str,
    seed_pages: list[str],
    max_bundles: int = 50,
    dry_run: bool = False,
) -> list[dict]:
    """Discover JS files, download, and scan for hardcoded secrets."""
    from html.parser import HTMLParser

    class _ScriptParser(HTMLParser):
        def __init__(self) -> None:
            super().__init__()
            self.scripts: list[str] = []
            self.inline: list[str] = []
            self._in_script = False
            self._buf = ""

        def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
            if tag == "script":
                ad = {k: v for k, v in attrs if v}
                if "src" in ad:
                    self.scripts.append(ad["src"])
                else:
                    self._in_script = True
                    self._buf = ""

        def handle_endtag(self, tag: str) -> None:
            if tag == "script" and self._in_script:
                self._in_script = False
                if self._buf.strip():
                    self.inline.append(self._buf)

        def handle_data(self, data: str) -> None:
            if self._in_script:
                self._buf += data

    js_urls: set[str] = set()
    inline_secrets: list[dict] = []

    # Step 1: Discover JS URLs from seed pages
    for path in seed_pages:
        url = urljoin(target, path)
        if dry_run:
            continue
        try:
            resp = session.get(url, allow_redirects=True)
            if resp.status_code >= 400 or "html" not in resp.headers.get("Content-Type", "").lower():
                continue
            parser = _ScriptParser()
            parser.feed(resp.text)

            for src in parser.scripts:
                full = urljoin(url, src)
                if full.endswith(".js") or ".js?" in full:
                    js_urls.add(full)

            # Scan inline scripts for secrets
            for script in parser.inline:
                secrets = _scan_text_for_secrets(script, f"{url} (inline)")
                if secrets:
                    inline_secrets.extend(secrets)

        except Exception as exc:
            log.warning("Error fetching %s: %s", url, exc)

    log.info("Discovered %d JS URLs from %d seed pages", len(js_urls), len(seed_pages))

    # Step 2: Download and scan JS files
    js_secrets: list[dict] = []
    for i, js_url in enumerate(sorted(js_urls)[:max_bundles]):
        if dry_run:
            log.info("[DRY-RUN] Would scan JS %s", js_url)
            continue
        try:
            resp = session.get(js_url, timeout=30)
            if resp.status_code != 200:
                continue
            secrets = _scan_text_for_secrets(resp.text, js_url)
            if secrets:
                js_secrets.extend(secrets)

            if (i + 1) % 10 == 0:
                log.info("Scanned %d/%d JS files", i + 1, len(js_urls))

        except Exception as exc:
            log.warning("Error scanning JS %s: %s", js_url, exc)

    return inline_secrets + js_secrets


# ---------------------------------------------------------------------------
# Phase 3: Source map analysis
# ---------------------------------------------------------------------------


def phase_source_map_scan(
    session: RateLimitedSession,
    target: str,
    seed_pages: list[str],
    max_maps: int = 20,
    dry_run: bool = False,
) -> list[dict]:
    """Find and download source maps, scan for secrets in original source."""
    from html.parser import HTMLParser

    class _ScriptSrcParser(HTMLParser):
        def __init__(self) -> None:
            super().__init__()
            self.scripts: list[str] = []

        def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
            if tag == "script":
                ad = {k: v for k, v in attrs if v}
                if "src" in ad:
                    self.scripts.append(ad["src"])

    sourcemap_ref = re.compile(r"""//[#@]\s*sourceMappingURL=\s*(\S+)""")
    map_findings: list[dict] = []
    checked_maps: set[str] = set()

    # Find JS files, then check for source maps
    js_urls: set[str] = set()
    for path in seed_pages:
        url = urljoin(target, path)
        if dry_run:
            continue
        try:
            resp = session.get(url, allow_redirects=True)
            if resp.status_code >= 400:
                continue
            parser = _ScriptSrcParser()
            parser.feed(resp.text)
            for src in parser.scripts:
                full = urljoin(url, src)
                if full.endswith(".js") or ".js?" in full:
                    js_urls.add(full)
        except Exception:
            pass

    for js_url in sorted(js_urls)[:max_maps * 3]:
        if dry_run:
            continue
        try:
            resp = session.get(js_url, timeout=30)
            if resp.status_code != 200:
                continue

            # Check for sourceMappingURL directive
            sm = sourcemap_ref.search(resp.text[-500:])  # Usually at end of file
            map_urls: list[str] = []
            if sm:
                ref = sm.group(1)
                if not ref.startswith("data:"):
                    map_urls.append(urljoin(js_url, ref))
            # Also try appending .map
            map_urls.append(js_url + ".map")

            for map_url in map_urls:
                if map_url in checked_maps:
                    continue
                checked_maps.add(map_url)

                try:
                    map_resp = session.get(map_url, timeout=15)
                    if map_resp.status_code != 200:
                        continue
                    ct = map_resp.headers.get("Content-Type", "")
                    # Validate it looks like a source map
                    body = map_resp.text[:500]
                    if '"mappings"' in body or '"sources"' in body:
                        # It's a real source map — scan for secrets
                        secrets = _scan_text_for_secrets(map_resp.text, map_url)

                        # Extract source file list
                        import json
                        try:
                            sm_data = json.loads(map_resp.text)
                            sources = sm_data.get("sources", [])
                        except Exception:
                            sources = []

                        entry = {
                            "map_url": map_url,
                            "js_url": js_url,
                            "size": len(map_resp.content),
                            "source_count": len(sources),
                            "sample_sources": sources[:15],
                        }
                        if secrets:
                            entry["secrets"] = secrets
                        map_findings.append(entry)

                        if len(map_findings) >= max_maps:
                            return map_findings

                except Exception:
                    pass

        except Exception as exc:
            log.warning("Error checking maps for %s: %s", js_url, exc)

    return map_findings


# ---------------------------------------------------------------------------
# Secret scanning helper
# ---------------------------------------------------------------------------


def _scan_text_for_secrets(text: str, source: str) -> list[dict]:
    """Scan a text blob for secret patterns. Returns list of matches."""
    results: list[dict] = []
    seen: set[str] = set()

    for pat in SECRET_PATTERNS:
        for m in pat["regex"].finditer(text):
            matched = m.group(1) if m.lastindex else m.group(0)
            # Deduplicate
            dedup_key = f"{pat['name']}:{matched[:30]}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            # False positive check
            if _is_false_positive(matched):
                continue

            # Redact the value for safe reporting (show first 6 + last 4 chars)
            redacted = _redact(matched)

            results.append({
                "type": pat["name"],
                "severity": pat["severity"],
                "source": source,
                "value_redacted": redacted,
                "match_length": len(matched),
                "context": _get_context(text, m.start(), 40),
            })

    return results


def _is_false_positive(value: str) -> bool:
    """Check if a matched value is likely a placeholder/test key."""
    lower = value.lower().strip("'\"")
    if any(fp in lower for fp in FALSE_POSITIVE_VALUES):
        return True
    # All same char
    if len(set(value.replace("-", "").replace("_", ""))) <= 2:
        return True
    # Too short
    if len(value) < 8:
        return True
    return False


def _redact(value: str) -> str:
    """Redact a secret value for safe reporting."""
    if len(value) <= 12:
        return value[:3] + "***" + value[-2:]
    return value[:6] + "..." + value[-4:]


def _get_context(text: str, pos: int, radius: int = 40) -> str:
    """Get surrounding context around a match position."""
    start = max(0, pos - radius)
    end = min(len(text), pos + radius)
    ctx = text[start:end].replace("\n", " ").replace("\r", "")
    return ctx


# ---------------------------------------------------------------------------
# Build findings
# ---------------------------------------------------------------------------


def build_findings(
    target: str,
    endpoint_results: list[dict],
    js_secrets: list[dict],
    sourcemap_results: list[dict],
) -> list[Finding]:
    """Convert raw results into Finding objects."""
    findings: list[Finding] = []

    # Group all secrets by severity
    all_secrets: list[dict] = []
    for ep in endpoint_results:
        all_secrets.extend(ep.get("secrets", []))
    all_secrets.extend(js_secrets)
    for sm in sourcemap_results:
        all_secrets.extend(sm.get("secrets", []))

    critical_secrets = [s for s in all_secrets if s["severity"] == "critical"]
    high_secrets = [s for s in all_secrets if s["severity"] == "high"]
    medium_secrets = [s for s in all_secrets if s["severity"] == "medium"]

    # CRITICAL: Exposed cloud/payment/private keys
    if critical_secrets:
        findings.append(Finding(
            title=f"CRITICAL secrets exposed ({len(critical_secrets)} found)",
            severity="critical",
            cwe="CWE-312",
            endpoint=target,
            description=(
                f"Found {len(critical_secrets)} critical secrets in HTTP responses and JS files. "
                "These include cloud provider keys, payment keys, private keys, or database "
                "connection strings that could lead to full account compromise."
            ),
            evidence={
                "count": len(critical_secrets),
                "types": list({s["type"] for s in critical_secrets}),
                "secrets": [
                    {"type": s["type"], "source": s["source"], "redacted": s["value_redacted"]}
                    for s in critical_secrets[:15]
                ],
            },
            impact="Full compromise: cloud infrastructure takeover, payment fraud, data breach.",
            remediation=(
                "Immediately rotate all exposed keys. Remove secrets from client-side code. "
                "Use environment variables or a secrets manager (Vault, AWS SSM, etc.)."
            ),
        ))

    # HIGH: Exposed tokens and API keys
    if high_secrets:
        findings.append(Finding(
            title=f"High-severity secrets exposed ({len(high_secrets)} found)",
            severity="high",
            cwe="CWE-540",
            endpoint=target,
            description=(
                f"Found {len(high_secrets)} high-severity secrets (API keys, tokens, webhooks) "
                "in HTTP responses or JavaScript files."
            ),
            evidence={
                "count": len(high_secrets),
                "types": list({s["type"] for s in high_secrets}),
                "secrets": [
                    {"type": s["type"], "source": s["source"], "redacted": s["value_redacted"]}
                    for s in high_secrets[:15]
                ],
            },
            impact="Account compromise, unauthorized API access, data exfiltration.",
            remediation="Rotate exposed tokens. Move secrets to server-side configuration.",
        ))

    # MEDIUM: Less critical leaks
    if medium_secrets:
        findings.append(Finding(
            title=f"Medium-severity secrets exposed ({len(medium_secrets)} found)",
            severity="medium",
            cwe="CWE-615",
            endpoint=target,
            description=(
                f"Found {len(medium_secrets)} medium-severity secrets (publishable keys, "
                "map tokens) in client-side code."
            ),
            evidence={
                "count": len(medium_secrets),
                "types": list({s["type"] for s in medium_secrets}),
                "secrets": [
                    {"type": s["type"], "source": s["source"], "redacted": s["value_redacted"]}
                    for s in medium_secrets[:10]
                ],
            },
            impact="Limited exposure but may aid further attacks.",
            remediation="Review necessity of client-side keys. Restrict key scopes.",
        ))

    # Sensitive endpoints accessible
    sensitive_eps = [ep for ep in endpoint_results if ep.get("note")]
    if sensitive_eps:
        findings.append(Finding(
            title=f"Sensitive endpoints accessible ({len(sensitive_eps)} found)",
            severity="medium",
            cwe="CWE-200",
            endpoint=target,
            description=(
                f"Found {len(sensitive_eps)} sensitive endpoints (.env, .git, actuator, debug) "
                "accessible without authentication."
            ),
            evidence={"endpoints": [{"url": ep["url"], "status": ep["status"]} for ep in sensitive_eps[:20]]},
            impact="Configuration disclosure, source code exposure, debug info leak.",
            remediation="Restrict access to sensitive endpoints. Remove debug endpoints in production.",
        ))

    # Source maps exposed
    if sourcemap_results:
        total_sources = sum(sm.get("source_count", 0) for sm in sourcemap_results)
        findings.append(Finding(
            title=f"Source maps exposed ({len(sourcemap_results)} maps, {total_sources} source files)",
            severity="high",
            cwe="CWE-540",
            endpoint=target,
            description=(
                f"Found {len(sourcemap_results)} JavaScript source maps accessible on the server. "
                f"Total of {total_sources} original source files exposed. Source maps reveal "
                "unminified code with comments, variable names, and potential secrets."
            ),
            evidence={
                "maps": [
                    {
                        "url": sm["map_url"],
                        "size": sm.get("size", 0),
                        "sources": sm.get("sample_sources", []),
                        "secrets_found": len(sm.get("secrets", [])),
                    }
                    for sm in sourcemap_results[:10]
                ],
            },
            impact="Full source code disclosure. May contain hardcoded secrets.",
            remediation="Remove .map files from production. Configure web server to block .map requests.",
        ))

    return findings


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = parse_base_args()
    parser.add_argument("--max-bundles", type=int, default=50,
                        help="Max JS bundles to scan")
    parser.add_argument("--max-maps", type=int, default=20,
                        help="Max source maps to analyze")
    parser.add_argument("--skip-sourcemaps", action="store_true",
                        help="Skip source map analysis phase")
    args = parser.parse_args()

    if args.verbose:
        import logging
        logging.getLogger().setLevel(logging.DEBUG)

    target = args.target.rstrip("/")
    config = load_config(args.config)

    # Merge config
    endpoints = config.get("endpoints", SECRET_ENDPOINTS)
    seed_pages = config.get("seed_pages", JS_DISCOVERY_PATHS)
    max_bundles = config.get("max_bundles", args.max_bundles)
    max_maps = config.get("max_maps", args.max_maps)

    log.info("=== Secret Leak Scanner ===")
    log.info("Target: %s", target)

    session = get_session_from_env()

    # Phase 1: Probe secret-bearing endpoints
    log.info("--- Phase 1: Probing secret-bearing endpoints (%d) ---", len(endpoints))
    endpoint_results = phase_probe_endpoints(session, target, endpoints, dry_run=args.dry_run)
    secret_eps = [ep for ep in endpoint_results if ep.get("secrets")]
    log.info("Found secrets in %d / %d probed endpoints", len(secret_eps), len(endpoints))

    # Phase 2: Scan JS bundles
    log.info("--- Phase 2: Scanning JS bundles for secrets ---")
    js_secrets = phase_scan_js_bundles(
        session, target, seed_pages, max_bundles=max_bundles, dry_run=args.dry_run
    )
    log.info("Found %d secrets in JS files", len(js_secrets))

    # Phase 3: Source map analysis
    sourcemap_results: list[dict] = []
    if not args.skip_sourcemaps:
        log.info("--- Phase 3: Source map analysis ---")
        sourcemap_results = phase_source_map_scan(
            session, target, seed_pages, max_maps=max_maps, dry_run=args.dry_run
        )
        log.info("Found %d exposed source maps", len(sourcemap_results))
    else:
        log.info("--- Phase 3: Skipped (--skip-sourcemaps) ---")

    # Build findings
    findings = build_findings(target, endpoint_results, js_secrets, sourcemap_results)

    log.info("=== Summary: %d findings ===", len(findings))
    for f in findings:
        log.info("  [%s] %s", f.severity.upper(), f.title)

    save_findings(findings, TOOL_NAME)
    return 0


if __name__ == "__main__":
    sys.exit(main())
