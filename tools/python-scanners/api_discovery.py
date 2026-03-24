#!/usr/bin/env python3
"""API Discovery Scanner — CWE-200, CWE-540 (Information Exposure).

Comprehensive API endpoint discovery combining:
  1. HTML page crawling — extract <script src>, <link href>, inline JS
  2. JS bundle analysis — regex scan for /api/ paths, hardcoded URLs, route tables
  3. Inline config extraction — window.__*, data-* attributes, meta tags, JSON-LD
  4. Endpoint enumeration — test discovered APIs with/without auth
  5. Source map detection — .js.map leaking full source code

Source: db_phase14b_apidiscovery.js + db_deep_probe.js from Doctolib bug bounty campaign.

Usage:
    python api_discovery.py --target https://example.com --dry-run
    python api_discovery.py --target https://example.com --config /configs/api-discovery-config.yaml

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import re
import sys
from html.parser import HTMLParser
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

TOOL_NAME = "api-discovery"

# ---------------------------------------------------------------------------
# Regex patterns — extracted from db_phase14b_apidiscovery.js
# ---------------------------------------------------------------------------

# API path patterns in JS bundles
API_PATH_PATTERNS = [
    re.compile(r"""['"`](/api/[a-zA-Z0-9_/{}:.\-]+)['"`]"""),
    re.compile(r"""['"`](/v[0-9]+/[a-zA-Z0-9_/{}:.\-]+)['"`]"""),
    re.compile(r"""['"`](https?://[^'"`\s]{5,200})['"`]"""),
    re.compile(r"""(?:fetch|axios|XMLHttpRequest)\s*\(\s*['"`]([^'"`\s]+)['"`]"""),
    re.compile(r"""\.(?:get|post|put|patch|delete)\s*\(\s*['"`]([^'"`\s]+)['"`]"""),
    re.compile(r"""(?:url|endpoint|path|route|api_url|baseURL)\s*[:=]\s*['"`]([^'"`\s]+)['"`]"""),
]

# Inline config patterns — from window.__INITIAL_STATE__, window.dl_constants, etc.
INLINE_CONFIG_PATTERNS = [
    re.compile(r"""window\.__([A-Z_]+)__\s*=\s*(\{.+?\});""", re.DOTALL),
    re.compile(r"""window\.([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(\{.+?\});""", re.DOTALL),
    re.compile(r"""<script[^>]*type\s*=\s*["']application/json["'][^>]*>(.*?)</script>""", re.DOTALL),
]

# Data attribute patterns
DATA_ATTR_PATTERN = re.compile(r"""data-(api[^=]*|url[^=]*|endpoint[^=]*|config[^=]*)=["']([^"']+)["']""")

# Meta tag patterns
META_PATTERN = re.compile(
    r"""<meta[^>]+(?:name|property)=["']([^"']*api[^"']*)["'][^>]+content=["']([^"']+)["']""",
    re.IGNORECASE,
)

# Route/path extraction from JS framework routers
ROUTER_PATTERNS = [
    re.compile(r"""path\s*:\s*['"`](/[^'"`]+)['"`]"""),               # Vue/React Router
    re.compile(r"""\.when\s*\(\s*['"`](/[^'"`]+)['"`]"""),            # AngularJS
    re.compile(r"""createRoute\s*\(\s*['"`](/[^'"`]+)['"`]"""),       # Generic
]

# Source map reference
SOURCEMAP_PATTERN = re.compile(r"""//[#@]\s*sourceMappingURL=\s*(\S+)""")

# Common API base paths to probe
DEFAULT_API_PATHS = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/graphql",
    "/graphiql",
    "/.well-known/openapi.json",
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/docs/api",
    "/api/docs",
    "/api/health",
    "/api/status",
    "/api/version",
    "/api/config",
    "/api/info",
    "/api/debug",
    "/api/me",
    "/api/user",
    "/api/users",
    "/api/account",
    "/api/session",
    "/api/settings",
    "/api/admin",
    "/_next/data",
    "/__nextjs_original-stack-frame",
]

# Seed pages to crawl (in addition to target root)
DEFAULT_SEED_PATHS = [
    "/",
    "/login",
    "/signin",
    "/signup",
    "/register",
    "/dashboard",
    "/app",
    "/home",
    "/account",
    "/settings",
    "/profile",
]


# ---------------------------------------------------------------------------
# HTML parser for script/link extraction
# ---------------------------------------------------------------------------


class ScriptLinkParser(HTMLParser):
    """Extract script src, link href, and inline scripts from HTML."""

    def __init__(self) -> None:
        super().__init__()
        self.scripts: list[str] = []
        self.links: list[str] = []
        self.inline_js: list[str] = []
        self.meta_tags: list[tuple[str, str]] = []
        self.data_attrs: list[tuple[str, str]] = []
        self._in_script = False
        self._current_script = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_dict = {k: v for k, v in attrs if v is not None}
        if tag == "script":
            if "src" in attr_dict:
                self.scripts.append(attr_dict["src"])
            else:
                self._in_script = True
                self._current_script = ""
        elif tag == "link" and attr_dict.get("rel") in ("stylesheet", "preload", "prefetch", "modulepreload"):
            if "href" in attr_dict:
                self.links.append(attr_dict["href"])
        elif tag == "meta":
            name = attr_dict.get("name") or attr_dict.get("property", "")
            content = attr_dict.get("content", "")
            if name and content:
                self.meta_tags.append((name, content))
        # Data attributes
        for k, v in attrs:
            if v and k.startswith("data-") and any(kw in k for kw in ("api", "url", "endpoint", "config", "key")):
                self.data_attrs.append((k, v))

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._in_script:
            self._in_script = False
            if self._current_script.strip():
                self.inline_js.append(self._current_script)

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self._current_script += data


# ---------------------------------------------------------------------------
# Phase 1: Crawl & extract JS references
# ---------------------------------------------------------------------------


def phase_crawl_pages(
    session: RateLimitedSession,
    target: str,
    seed_paths: list[str],
    dry_run: bool = False,
) -> tuple[list[str], list[str], list[dict]]:
    """Crawl seed pages, return (js_urls, inline_scripts, data_attrs)."""
    js_urls: set[str] = set()
    inline_scripts: list[str] = []
    data_attrs_found: list[dict] = []

    for path in seed_paths:
        url = urljoin(target, path)
        if dry_run:
            log.info("[DRY-RUN] Would crawl %s", url)
            continue
        try:
            resp = session.get(url, allow_redirects=True)
            if resp.status_code >= 400:
                continue
            ct = resp.headers.get("Content-Type", "")
            if "html" not in ct.lower():
                continue

            parser = ScriptLinkParser()
            parser.feed(resp.text)

            for src in parser.scripts:
                full_url = urljoin(url, src)
                if full_url.endswith(".js") or ".js?" in full_url:
                    js_urls.add(full_url)

            inline_scripts.extend(parser.inline_js)

            for name, val in parser.data_attrs:
                data_attrs_found.append({"page": path, "attr": name, "value": val})
            for name, val in parser.meta_tags:
                data_attrs_found.append({"page": path, "meta": name, "value": val})

            # Also extract from inline JS config patterns
            for pat in INLINE_CONFIG_PATTERNS:
                for m in pat.finditer(resp.text):
                    inline_scripts.append(m.group(0))

            log.info("Crawled %s — %d scripts, %d inline", path, len(parser.scripts), len(parser.inline_js))

        except Exception as exc:
            log.warning("Error crawling %s: %s", url, exc)

    return sorted(js_urls), inline_scripts, data_attrs_found


# ---------------------------------------------------------------------------
# Phase 2: Download & analyze JS bundles
# ---------------------------------------------------------------------------


def phase_analyze_js_bundles(
    session: RateLimitedSession,
    target: str,
    js_urls: list[str],
    max_bundles: int = 50,
    dry_run: bool = False,
) -> tuple[set[str], list[dict]]:
    """Download JS files, extract API paths and source map references."""
    discovered_apis: set[str] = set()
    sourcemaps: list[dict] = []

    for i, js_url in enumerate(js_urls[:max_bundles]):
        if dry_run:
            log.info("[DRY-RUN] Would fetch JS bundle %s", js_url)
            continue
        try:
            resp = session.get(js_url, timeout=30)
            if resp.status_code != 200:
                continue
            content = resp.text

            # Extract API paths
            for pat in API_PATH_PATTERNS:
                for m in pat.finditer(content):
                    path = m.group(1)
                    # Filter noise: skip obvious CSS/image/font paths
                    if _is_api_candidate(path):
                        discovered_apis.add(path)

            # Extract router paths
            for pat in ROUTER_PATTERNS:
                for m in pat.finditer(content):
                    discovered_apis.add(m.group(1))

            # Check for source maps
            sm_match = SOURCEMAP_PATTERN.search(content)
            if sm_match:
                sm_ref = sm_match.group(1)
                sm_url = urljoin(js_url, sm_ref)
                sourcemaps.append({"js_url": js_url, "map_url": sm_url, "ref": sm_ref})

            # Also check for .map via HEAD request
            map_url = js_url + ".map"
            try:
                map_resp = session.get(map_url, timeout=10, stream=True)
                if map_resp.status_code == 200:
                    ct = map_resp.headers.get("Content-Type", "")
                    if "json" in ct or "javascript" in ct or "octet-stream" in ct:
                        sourcemaps.append({"js_url": js_url, "map_url": map_url, "ref": ".map appended"})
                map_resp.close()
            except Exception:
                pass

            if (i + 1) % 10 == 0:
                log.info("Analyzed %d/%d JS bundles, found %d APIs", i + 1, len(js_urls[:max_bundles]),
                         len(discovered_apis))

        except Exception as exc:
            log.warning("Error fetching JS %s: %s", js_url, exc)

    return discovered_apis, sourcemaps


def _is_api_candidate(path: str) -> bool:
    """Filter out non-API paths (CSS, images, fonts, etc.)."""
    skip_ext = (".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2",
                ".ttf", ".eot", ".ico", ".webp", ".mp4", ".mp3", ".pdf")
    skip_prefix = ("/static/", "/assets/", "/images/", "/img/", "/fonts/", "/css/", "/media/")
    lower = path.lower()
    if any(lower.endswith(ext) for ext in skip_ext):
        return False
    if any(lower.startswith(p) for p in skip_prefix):
        return False
    if len(path) < 3 or len(path) > 200:
        return False
    return True


# ---------------------------------------------------------------------------
# Phase 3: Extract inline configs (window.*, JSON-LD, etc.)
# ---------------------------------------------------------------------------


def phase_extract_inline_configs(
    inline_scripts: list[str],
    data_attrs: list[dict],
) -> list[dict]:
    """Parse inline JS scripts for global config objects."""
    configs_found: list[dict] = []

    for script in inline_scripts:
        # window.__CONFIG__ = {...}
        for pat in INLINE_CONFIG_PATTERNS:
            for m in pat.finditer(script):
                try:
                    import json
                    raw = m.group(2) if m.lastindex and m.lastindex >= 2 else m.group(1)
                    # Try parsing as JSON — best effort
                    data = json.loads(raw)
                    configs_found.append({
                        "type": "inline_config",
                        "variable": m.group(1) if m.lastindex and m.lastindex >= 2 else "json_block",
                        "keys": list(data.keys()) if isinstance(data, dict) else str(type(data)),
                        "size": len(raw),
                    })
                except (json.JSONDecodeError, IndexError):
                    configs_found.append({
                        "type": "inline_config",
                        "variable": m.group(1) if m.lastindex else "unknown",
                        "size": len(m.group(0)),
                        "preview": m.group(0)[:200],
                    })

    for attr in data_attrs:
        configs_found.append({"type": "data_attribute", **attr})

    return configs_found


# ---------------------------------------------------------------------------
# Phase 4: Enumerate discovered endpoints
# ---------------------------------------------------------------------------


def phase_enumerate_endpoints(
    session: RateLimitedSession,
    target: str,
    discovered_apis: set[str],
    extra_paths: list[str],
    dry_run: bool = False,
) -> list[dict]:
    """Test discovered + default API paths, return accessible ones."""
    results: list[dict] = []
    all_paths = sorted(set(list(discovered_apis) + extra_paths))

    for path in all_paths:
        # Resolve relative vs absolute URLs
        if path.startswith("http://") or path.startswith("https://"):
            url = path
        else:
            url = urljoin(target, path)

        # Scope check — skip external URLs
        if urlparse(url).netloc != urlparse(target).netloc:
            continue

        if dry_run:
            log.info("[DRY-RUN] Would probe %s", url)
            results.append({"url": url, "status": "dry-run"})
            continue

        try:
            resp = session.get(url, allow_redirects=False)
            entry = {
                "url": url,
                "path": path,
                "status": resp.status_code,
                "content_type": resp.headers.get("Content-Type", ""),
                "size": len(resp.content),
            }

            # Check if we got meaningful JSON
            if resp.status_code < 400 and "json" in entry["content_type"].lower():
                entry["has_json_body"] = True
                try:
                    import json
                    body = resp.json()
                    if isinstance(body, dict):
                        entry["json_keys"] = list(body.keys())[:20]
                        entry["json_key_count"] = len(body.keys())
                except Exception:
                    pass

            results.append(entry)

        except Exception as exc:
            log.warning("Error probing %s: %s", url, exc)

    return results


# ---------------------------------------------------------------------------
# Build findings
# ---------------------------------------------------------------------------


def build_findings(
    target: str,
    discovered_apis: set[str],
    accessible_endpoints: list[dict],
    sourcemaps: list[dict],
    inline_configs: list[dict],
    data_attrs: list[dict],
) -> list[Finding]:
    """Convert raw results into Finding objects."""
    findings: list[Finding] = []

    # Finding: accessible undocumented APIs
    accessible_json = [e for e in accessible_endpoints
                       if isinstance(e.get("status"), int) and 200 <= e["status"] < 300
                       and e.get("has_json_body")]
    if accessible_json:
        findings.append(Finding(
            title=f"Undocumented API endpoints discovered ({len(accessible_json)} accessible)",
            severity="medium",
            cwe="CWE-200",
            endpoint=target,
            description=(
                f"Discovered {len(discovered_apis)} API endpoints in JS bundles and HTML. "
                f"{len(accessible_json)} returned valid JSON responses, potentially exposing "
                "internal data or undocumented functionality."
            ),
            evidence={
                "total_discovered": len(discovered_apis),
                "accessible_json_count": len(accessible_json),
                "sample_endpoints": [e["url"] for e in accessible_json[:10]],
                "sample_keys": [
                    {"url": e["url"], "keys": e.get("json_keys", [])}
                    for e in accessible_json[:5] if e.get("json_keys")
                ],
            },
            impact="Information exposure through undocumented APIs. May leak internal data structures.",
            remediation="Audit all discovered endpoints. Remove or restrict access to internal APIs.",
        ))

    # Finding: source maps exposed
    if sourcemaps:
        findings.append(Finding(
            title=f"Source maps exposed ({len(sourcemaps)} files)",
            severity="high",
            cwe="CWE-540",
            endpoint=target,
            description=(
                f"Found {len(sourcemaps)} JavaScript source map files accessible on the server. "
                "Source maps reveal the original unminified source code, including comments, "
                "variable names, API keys, and internal logic."
            ),
            evidence={"sourcemaps": sourcemaps[:20]},
            impact="Full source code disclosure. May contain hardcoded secrets, API keys, internal endpoints.",
            remediation="Remove .map files from production servers or restrict access via server config.",
        ))

    # Finding: inline configs with sensitive data
    sensitive_configs = [c for c in inline_configs
                         if c.get("type") == "inline_config" and c.get("size", 0) > 100]
    if sensitive_configs:
        findings.append(Finding(
            title=f"Inline JavaScript configs exposed ({len(sensitive_configs)} objects)",
            severity="medium",
            cwe="CWE-200",
            endpoint=target,
            description=(
                f"Found {len(sensitive_configs)} inline JavaScript configuration objects "
                "(window.__*, JSON blocks). These may expose internal settings, API endpoints, "
                "feature flags, or application state."
            ),
            evidence={"configs": sensitive_configs[:10]},
            impact="Application internals exposed to client. May reveal hidden features or debug endpoints.",
            remediation="Minimize data exposed in inline configs. Move sensitive configuration server-side.",
        ))

    # Finding: data attributes with API info
    api_attrs = [a for a in data_attrs if any(kw in a.get("attr", "").lower()
                 for kw in ("api", "url", "endpoint", "key", "token"))]
    if api_attrs:
        findings.append(Finding(
            title=f"Sensitive data attributes found ({len(api_attrs)} elements)",
            severity="low",
            cwe="CWE-200",
            endpoint=target,
            description=(
                f"Found {len(api_attrs)} HTML data attributes containing API URLs, "
                "endpoint references, or potentially sensitive keys."
            ),
            evidence={"data_attributes": api_attrs[:20]},
            impact="Information leakage through HTML data attributes.",
            remediation="Review data-* attributes for unnecessary data exposure.",
        ))

    return findings


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = parse_base_args()
    parser.add_argument("--max-bundles", type=int, default=50,
                        help="Max JS bundles to download and analyze")
    args = parser.parse_args()

    if args.verbose:
        import logging
        logging.getLogger().setLevel(logging.DEBUG)

    target = args.target.rstrip("/")
    config = load_config(args.config)

    # Merge config
    seed_paths = config.get("seed_paths", DEFAULT_SEED_PATHS)
    extra_api_paths = config.get("api_paths", DEFAULT_API_PATHS)
    max_bundles = config.get("max_bundles", args.max_bundles)

    log.info("=== API Discovery Scanner ===")
    log.info("Target: %s", target)

    session = get_session_from_env()

    # Phase 1: Crawl pages
    log.info("--- Phase 1: Crawling seed pages ---")
    js_urls, inline_scripts, data_attrs = phase_crawl_pages(
        session, target, seed_paths, dry_run=args.dry_run
    )
    log.info("Found %d JS URLs, %d inline scripts, %d data attributes",
             len(js_urls), len(inline_scripts), len(data_attrs))

    # Phase 2: Analyze JS bundles
    log.info("--- Phase 2: Analyzing JS bundles ---")
    discovered_apis, sourcemaps = phase_analyze_js_bundles(
        session, target, js_urls, max_bundles=max_bundles, dry_run=args.dry_run
    )
    log.info("Discovered %d API paths, %d source maps", len(discovered_apis), len(sourcemaps))

    # Phase 3: Extract inline configs
    log.info("--- Phase 3: Extracting inline configs ---")
    inline_configs = phase_extract_inline_configs(inline_scripts, data_attrs)
    log.info("Found %d inline configs", len(inline_configs))

    # Phase 4: Enumerate endpoints
    log.info("--- Phase 4: Enumerating endpoints ---")
    accessible_endpoints = phase_enumerate_endpoints(
        session, target, discovered_apis, extra_api_paths, dry_run=args.dry_run
    )
    accessible_count = len([e for e in accessible_endpoints if isinstance(e.get("status"), int) and e["status"] < 400])
    log.info("Probed %d endpoints, %d accessible", len(accessible_endpoints), accessible_count)

    # Build findings
    findings = build_findings(
        target, discovered_apis, accessible_endpoints,
        sourcemaps, inline_configs, data_attrs,
    )

    log.info("=== Summary: %d findings ===", len(findings))
    for f in findings:
        log.info("  [%s] %s", f.severity.upper(), f.title)

    save_findings(findings, TOOL_NAME)
    return 0


if __name__ == "__main__":
    sys.exit(main())
