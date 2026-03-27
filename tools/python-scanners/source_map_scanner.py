#!/usr/bin/env python3
"""Source Map Scanner — Discover JS .map files and extract secrets (CWE-215/798).

Scans for exposed JavaScript source maps that may leak:
- Source code (original TypeScript/JSX)
- API keys, tokens, secrets in source
- Internal paths and infrastructure details
- Environment variables baked into builds

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import json
import re
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from lib import (
    Finding, RateLimitedSession, get_session_from_env, log,
    parse_base_args, save_findings, load_config,
)

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

COMMON_JS_PATHS = [
    "/static/js/", "/assets/js/", "/dist/", "/build/static/js/",
    "/_next/static/chunks/", "/_next/static/", "/js/", "/scripts/",
    "/bundles/", "/vendor/",
]

SECRET_PATTERNS = [
    (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', "API Key", "critical"),
    (r'(?:secret|token|password|passwd|pwd)\s*[:=]\s*["\']([^\s"\']{8,})["\']', "Secret/Token", "critical"),
    (r'(?:aws[_-]?access|AKIA)[A-Z0-9]{12,}', "AWS Access Key", "critical"),
    (r'(?:sk-[a-zA-Z0-9]{20,})', "OpenAI/Stripe Secret Key", "critical"),
    (r'(?:ghp_[a-zA-Z0-9]{36})', "GitHub Personal Token", "critical"),
    (r'(?:Bearer\s+[a-zA-Z0-9\-._~+/]+=*)', "Bearer Token", "high"),
    (r'(?:mongodb(?:\+srv)?://[^\s"\']+)', "MongoDB Connection String", "critical"),
    (r'(?:postgres(?:ql)?://[^\s"\']+)', "PostgreSQL Connection String", "critical"),
    (r'(?:redis://[^\s"\']+)', "Redis Connection String", "high"),
    (r'(?:https?://[^/\s]+\.internal\.[^\s"\']+)', "Internal URL", "medium"),
    (r'(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?::\d+)?', "Internal IP", "low"),
]

SOURCEMAP_EXTENSIONS = [".map", ".js.map", ".css.map"]

SOURCEMAP_HEADER = "SourceMap"
X_SOURCEMAP_HEADER = "X-SourceMap"


def discover_js_files(
    session: RateLimitedSession,
    target: str,
    dry_run: bool = False,
) -> list[str]:
    """Discover JS files from the main page and common paths."""
    js_urls: list[str] = []

    # Fetch main page and extract script src
    if dry_run:
        log.info("[DRY-RUN] GET %s", target)
        return []

    try:
        resp = session.get(target)
        # Extract script src attributes
        script_pattern = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.IGNORECASE)
        for match in script_pattern.finditer(resp.text):
            src = match.group(1)
            if src.startswith("//"):
                src = "https:" + src
            elif src.startswith("/"):
                src = target.rstrip("/") + src
            elif not src.startswith("http"):
                src = target.rstrip("/") + "/" + src
            js_urls.append(src)

        # Also extract from link rel=preload
        preload_pattern = re.compile(r'<link[^>]+href=["\']([^"\']+\.js[^"\']*)["\'][^>]+as=["\']script["\']', re.IGNORECASE)
        for match in preload_pattern.finditer(resp.text):
            src = match.group(1)
            if src.startswith("/"):
                src = target.rstrip("/") + src
            js_urls.append(src)

    except Exception as e:
        log.warning("Failed to fetch main page: %s", e)

    return list(set(js_urls))


def check_sourcemap(
    session: RateLimitedSession,
    js_url: str,
    dry_run: bool = False,
) -> tuple[str | None, str | None]:
    """Check if a JS file has a source map (via header or inline comment)."""
    if dry_run:
        return None, None

    try:
        resp = session.get(js_url)

        # Check response headers
        for hdr in (SOURCEMAP_HEADER, X_SOURCEMAP_HEADER):
            if hdr.lower() in {k.lower(): v for k, v in resp.headers.items()}:
                map_url = resp.headers.get(hdr) or resp.headers.get(hdr.lower())
                if map_url:
                    if not map_url.startswith("http"):
                        base = js_url.rsplit("/", 1)[0]
                        map_url = base + "/" + map_url
                    return map_url, "header"

        # Check inline comment
        comment_pattern = re.compile(r'//[#@]\s*sourceMappingURL=(\S+)')
        match = comment_pattern.search(resp.text[-500:])  # Check end of file
        if match:
            map_url = match.group(1)
            if not map_url.startswith("http"):
                if not map_url.startswith("data:"):
                    base = js_url.rsplit("/", 1)[0]
                    map_url = base + "/" + map_url
                else:
                    return None, None  # data: URIs are inline, not fetchable
            return map_url, "inline-comment"

    except Exception as e:
        log.debug("Check sourcemap error for %s: %s", js_url, e)

    return None, None


def analyze_sourcemap(
    session: RateLimitedSession,
    map_url: str,
    dry_run: bool = False,
) -> tuple[dict | None, list[dict]]:
    """Fetch and analyze a source map for secrets."""
    secrets_found: list[dict] = []

    if dry_run:
        return None, secrets_found

    try:
        resp = session.get(map_url, timeout=30)
        if resp.status_code != 200:
            return None, secrets_found

        try:
            data = resp.json()
        except json.JSONDecodeError:
            return None, secrets_found

        # Check sources list for interesting paths
        sources = data.get("sources", [])

        # Check sourcesContent for secrets
        contents = data.get("sourcesContent", [])
        for i, content in enumerate(contents):
            if not content:
                continue
            source_name = sources[i] if i < len(sources) else f"source_{i}"

            for pattern, secret_type, severity in SECRET_PATTERNS:
                for match in re.finditer(pattern, content):
                    # Mask the actual secret value
                    value = match.group(0)
                    masked = value[:6] + "***" + value[-4:] if len(value) > 10 else "***"
                    secrets_found.append({
                        "type": secret_type,
                        "severity": severity,
                        "source": source_name,
                        "masked_value": masked,
                    })

        return {"sources_count": len(sources), "has_content": len(contents) > 0}, secrets_found

    except Exception as e:
        log.debug("Analyze sourcemap error: %s", e)
        return None, secrets_found


# ---------------------------------------------------------------------------
# Main scan
# ---------------------------------------------------------------------------


def scan(
    session: RateLimitedSession,
    target: str,
    dry_run: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []

    # Phase 1: Discover JS files
    log.info("--- Phase 1: Discovering JS files ---")
    js_urls = discover_js_files(session, target, dry_run)
    log.info("Found %d JS files", len(js_urls))

    # Phase 2: Check for source maps
    log.info("--- Phase 2: Checking for source maps ---")
    for js_url in js_urls:
        map_url, method = check_sourcemap(session, js_url, dry_run)
        if not map_url:
            continue

        findings.append(Finding(
            title=f"Exposed Source Map: {js_url.split('/')[-1]}",
            severity="medium",
            cwe="CWE-215",
            endpoint=map_url,
            method="GET",
            description=f"Source map found via {method} for {js_url}",
            steps=[
                f"Fetch JS file: {js_url}",
                f"Source map reference found via {method}",
                f"Source map accessible at: {map_url}",
            ],
            impact="Source code exposure, potential secret leakage",
            evidence={"js_url": js_url, "map_url": map_url, "detection": method},
            remediation="Remove source maps from production. Configure build to exclude .map files.",
        ))

        # Phase 3: Analyze source map contents
        log.info("Analyzing source map: %s", map_url)
        info, secrets = analyze_sourcemap(session, map_url, dry_run)
        if info:
            log.info("  Sources: %d, Has content: %s", info["sources_count"], info["has_content"])

        for secret in secrets:
            findings.append(Finding(
                title=f"Secret in Source Map: {secret['type']}",
                severity=secret["severity"],
                cwe="CWE-798",
                endpoint=map_url,
                method="GET",
                description=f"{secret['type']} found in source map file ({secret['source']})",
                steps=[
                    f"Download source map: {map_url}",
                    f"Inspect sourcesContent for {secret['source']}",
                    f"Found {secret['type']}: {secret['masked_value']}",
                ],
                impact="Credential exposure via source map. Attacker can extract secrets.",
                evidence=secret,
                remediation="Remove secrets from frontend code. Use environment variables server-side only.",
            ))

    # Phase 4: Brute-force common .map paths
    log.info("--- Phase 3: Brute-force .map paths ---")
    for path in COMMON_JS_PATHS:
        for ext in ["main.js.map", "app.js.map", "bundle.js.map", "vendor.js.map", "chunk.js.map"]:
            url = f"{target.rstrip('/')}{path}{ext}"
            if dry_run:
                log.info("[DRY-RUN] GET %s", url)
                continue
            try:
                resp = session.get(url, timeout=10)
                if resp.status_code == 200 and resp.headers.get("content-type", "").startswith("application/json"):
                    findings.append(Finding(
                        title=f"Source Map via Brute Force: {path}{ext}",
                        severity="medium",
                        cwe="CWE-215",
                        endpoint=url,
                        method="GET",
                        description=f"Source map found at predictable path {path}{ext}",
                        steps=[f"GET {url}", f"Status: {resp.status_code}"],
                        impact="Source code and potential secrets exposed",
                        evidence={"status": resp.status_code, "size": len(resp.content)},
                        remediation="Remove source maps from production deployments.",
                    ))
            except Exception:
                pass

    return findings


def main() -> None:
    parser = parse_base_args()
    args = parser.parse_args()

    if args.verbose:
        import logging
        logging.getLogger().setLevel(logging.DEBUG)

    session = get_session_from_env()
    if args.rate_limit:
        session.min_interval = 1.0 / args.rate_limit

    log.info("=== Source Map Scanner starting on %s ===", args.target)
    all_findings = scan(session, args.target, args.dry_run)
    log.info("=== Source Map Scanner complete: %d findings ===", len(all_findings))
    save_findings(all_findings, "source-map")


if __name__ == "__main__":
    main()
