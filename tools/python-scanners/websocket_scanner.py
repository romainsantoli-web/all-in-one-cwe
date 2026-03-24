#!/usr/bin/env python3
"""WebSocket security scanner — auth bypass, origin validation, injection.

CWE-284 (Improper Access Control), CWE-345 (Insufficient Verification of Data Authenticity)

Checks:
- Origin header enforcement (can we connect from evil origin?)
- Authentication bypass (connect without valid token)
- JSON injection via WebSocket frames
- Cross-protocol hijacking indicators

Usage:
    python websocket_scanner.py --target ws://example.com/ws
    python websocket_scanner.py --target https://example.com --endpoints /ws,/socket.io,/graphql-ws

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import argparse
import json
import ssl
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

try:
    import websocket as ws_lib
except ImportError:
    print("websocket-client required: pip install websocket-client")
    sys.exit(1)

OUTPUT_DIR = Path("/output") if Path("/output").exists() else Path("reports/websocket-scanner")

# Common WebSocket endpoints to probe
DEFAULT_WS_PATHS = [
    "/ws", "/wss", "/websocket", "/socket", "/socket.io/",
    "/graphql-ws", "/subscriptions", "/cable", "/realtime",
    "/hub", "/signalr", "/chat", "/stream", "/events",
]

# Injection payloads for testing
INJECTION_PAYLOADS = [
    '{"type":"subscribe","query":"{ __schema { types { name } } }"}',
    '{"action":"admin","data":"test"}',
    '<script>alert(1)</script>',
    '{"$where":"1==1"}',
    '{"__proto__":{"polluted":true}}',
]


def _make_ws_url(target: str, path: str = "") -> str:
    """Convert HTTP(S) URL to WS(S) URL."""
    parsed = urlparse(target)
    if parsed.scheme in ("ws", "wss"):
        return target + path
    scheme = "wss" if parsed.scheme == "https" else "ws"
    host = parsed.netloc or parsed.path
    return f"{scheme}://{host}{path}"


def _try_connect(url: str, headers: dict | None = None, timeout: int = 5) -> dict:
    """Attempt WebSocket connection, return result dict."""
    result = {"url": url, "connected": False, "error": None, "server_headers": {}}
    try:
        _ws = ws_lib.create_connection(
            url,
            header=headers or {},
            timeout=timeout,
            sslopt={"cert_reqs": ssl.CERT_NONE},
        )
        result["connected"] = True
        result["server_headers"] = dict(_ws.getheaders()) if hasattr(_ws, "getheaders") else {}
        _ws.close()
    except ws_lib.WebSocketBadStatusException as e:
        result["error"] = f"HTTP {e.status_code}"
        result["status_code"] = e.status_code
    except ws_lib.WebSocketException as e:
        result["error"] = str(e)
    except Exception as e:
        result["error"] = str(e)
    return result


def check_origin_bypass(ws_url: str) -> list[dict]:
    """Test if WebSocket accepts connections from arbitrary origins (CWE-346)."""
    findings = []
    evil_origins = ["https://evil.com", "null", "https://attacker.local"]

    # First, try with legitimate origin
    parsed = urlparse(ws_url)
    legit_origin = f"{parsed.scheme.replace('ws', 'http')}://{parsed.netloc}"
    baseline = _try_connect(ws_url, {"Origin": legit_origin})

    if not baseline["connected"]:
        return findings  # Can't connect even legitimately

    for origin in evil_origins:
        result = _try_connect(ws_url, {"Origin": origin})
        if result["connected"]:
            findings.append({
                "id": f"ws-origin-bypass-{origin.replace('https://', '').replace(':', '')}",
                "name": f"WebSocket Origin Bypass ({origin})",
                "severity": "high",
                "cwe": "CWE-346",
                "url": ws_url,
                "detail": f"WebSocket accepts connections from arbitrary Origin: {origin}",
                "evidence": json.dumps({"origin_tested": origin, "connected": True}),
            })
    return findings


def check_auth_bypass(ws_url: str) -> list[dict]:
    """Test if WebSocket is accessible without authentication (CWE-284)."""
    findings = []

    # Try connecting with no auth
    result = _try_connect(ws_url)
    if result["connected"]:
        findings.append({
            "id": "ws-no-auth",
            "name": "WebSocket Accessible Without Authentication",
            "severity": "high",
            "cwe": "CWE-284",
            "url": ws_url,
            "detail": "WebSocket endpoint accepts connections without authentication tokens",
            "evidence": json.dumps({"connected": True, "headers_sent": "none"}),
        })

    # Try with empty/invalid auth
    for header_name in ["Authorization", "Cookie", "Sec-WebSocket-Protocol"]:
        result = _try_connect(ws_url, {header_name: "invalid-token-12345"})
        if result["connected"]:
            findings.append({
                "id": f"ws-auth-bypass-{header_name.lower()}",
                "name": f"WebSocket Auth Bypass via {header_name}",
                "severity": "high",
                "cwe": "CWE-287",
                "url": ws_url,
                "detail": f"WebSocket accepts invalid {header_name} header",
                "evidence": json.dumps({"header": header_name, "value": "invalid-token-12345"}),
            })

    return findings


def check_injection(ws_url: str, timeout: int = 5) -> list[dict]:
    """Send injection payloads and check for interesting responses."""
    findings = []
    try:
        _ws = ws_lib.create_connection(
            ws_url, timeout=timeout,
            sslopt={"cert_reqs": ssl.CERT_NONE},
        )
    except Exception:
        return findings

    for payload in INJECTION_PAYLOADS:
        try:
            _ws.send(payload)
            time.sleep(0.5)
            _ws.settimeout(2)
            try:
                response = _ws.recv()
            except ws_lib.WebSocketTimeoutException:
                continue

            resp_lower = response.lower() if isinstance(response, str) else response.decode("utf-8", errors="ignore").lower()

            # Check for error leaks
            error_indicators = ["stack trace", "traceback", "exception", "syntax error", "unexpected token"]
            for indicator in error_indicators:
                if indicator in resp_lower:
                    findings.append({
                        "id": f"ws-error-leak-{indicator.replace(' ', '-')}",
                        "name": f"WebSocket Error Information Leak ({indicator})",
                        "severity": "medium",
                        "cwe": "CWE-209",
                        "url": ws_url,
                        "detail": f"WebSocket leaks error details ({indicator}) in response to malformed input",
                        "evidence": json.dumps({"payload": payload, "response_snippet": resp_lower[:200]}),
                    })
                    break

            # Check for GraphQL introspection success
            if "__schema" in resp_lower or '"types"' in resp_lower:
                findings.append({
                    "id": "ws-graphql-introspection",
                    "name": "GraphQL Introspection Enabled via WebSocket",
                    "severity": "medium",
                    "cwe": "CWE-200",
                    "url": ws_url,
                    "detail": "GraphQL introspection query succeeded over WebSocket",
                    "evidence": json.dumps({"payload": payload, "response_snippet": resp_lower[:500]}),
                })

        except Exception:
            continue

    try:
        _ws.close()
    except Exception:
        pass

    return findings


def discover_endpoints(target: str, paths: list[str]) -> list[str]:
    """Discover active WebSocket endpoints."""
    active = []
    for path in paths:
        url = _make_ws_url(target, path)
        result = _try_connect(url)
        if result["connected"] or (result.get("status_code") and result["status_code"] in (101, 200, 401, 403)):
            active.append(url)
    return active


def main() -> None:
    parser = argparse.ArgumentParser(description="WebSocket security scanner")
    parser.add_argument("--target", "-t", required=True, help="Target URL (ws:// or http://)")
    parser.add_argument("--endpoints", "-e", default="", help="Comma-separated WS paths to test")
    parser.add_argument("--rate-limit", type=int, default=50)
    parser.add_argument("--config", help="Config YAML path")
    parser.add_argument("--output", "-o", default=str(OUTPUT_DIR / "results.json"))
    args = parser.parse_args()

    # Build endpoint list
    if args.endpoints:
        paths = [p.strip() for p in args.endpoints.split(",")]
    else:
        paths = DEFAULT_WS_PATHS

    print(f"[*] WebSocket Scanner — Target: {args.target}")
    print(f"[*] Testing {len(paths)} endpoints...")

    # Discover active endpoints
    active_urls = discover_endpoints(args.target, paths)
    print(f"[+] Found {len(active_urls)} active WebSocket endpoints")

    # Also test the raw target if it's already a ws:// URL
    if urlparse(args.target).scheme in ("ws", "wss"):
        if args.target not in active_urls:
            active_urls.insert(0, args.target)

    all_findings: list[dict] = []

    for ws_url in active_urls:
        print(f"\n[*] Scanning: {ws_url}")

        # Origin bypass
        origin_findings = check_origin_bypass(ws_url)
        print(f"  Origin bypass: {len(origin_findings)} findings")
        all_findings.extend(origin_findings)

        # Auth bypass
        auth_findings = check_auth_bypass(ws_url)
        print(f"  Auth bypass: {len(auth_findings)} findings")
        all_findings.extend(auth_findings)

        # Injection
        inject_findings = check_injection(ws_url)
        print(f"  Injection: {len(inject_findings)} findings")
        all_findings.extend(inject_findings)

        time.sleep(1.0 / max(args.rate_limit, 1))

    # Write output
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(all_findings, indent=2))

    # Summary
    print(f"\n{'='*50}")
    print(f"Total findings: {len(all_findings)}")
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = sum(1 for f in all_findings if f.get("severity") == sev)
        if count:
            print(f"  {sev.upper()}: {count}")
    print(f"Output: {args.output}")


if __name__ == "__main__":
    main()
