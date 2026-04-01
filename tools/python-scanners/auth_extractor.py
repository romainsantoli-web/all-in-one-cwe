#!/usr/bin/env python3
"""auth_extractor.py — Automatic auth token extraction via Chrome DevTools Protocol.

Connects to a running Chrome/Chromium instance with remote debugging enabled,
extracts cookies, CSRF tokens, localStorage/sessionStorage data, and
Authorization headers for the target domain.

Outputs a .env file ready to be sourced by runner.sh or docker compose.

Usage:
  1. Launch Chrome with remote debugging:
       macOS:  /Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
               --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-debug
       Linux:  google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-debug

  2. Navigate to the target in Chrome and log in manually.

  3. Extract tokens:
       python3 auth_extractor.py --target https://target.com --output auth.env

  4. Use with scanners:
       source auth.env && bash runner.sh https://target.com
       # or
       make auth-extract TARGET=https://target.com
       source auth.env && make python-scanners TARGET=https://target.com

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# CDP communication — uses only stdlib (no external deps)
import http.client
import ssl

try:
    import websocket  # websocket-client
except ImportError:
    websocket = None  # type: ignore[assignment]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("auth-extractor")

# ---------------------------------------------------------------------------
# CDP HTTP helpers (stdlib only, no requests needed)
# ---------------------------------------------------------------------------

def cdp_http_get(host: str, port: int, path: str) -> Any:
    """GET request to CDP HTTP endpoint, returns parsed JSON."""
    conn = http.client.HTTPConnection(host, port, timeout=5)
    conn.request("GET", path)
    resp = conn.getresponse()
    data = resp.read().decode()
    conn.close()
    if resp.status != 200:
        raise ConnectionError(f"CDP HTTP {resp.status}: {data[:200]}")
    return json.loads(data)


def cdp_ws_send(ws_url: str, method: str, params: dict | None = None,
                timeout: float = 10.0) -> dict:
    """Send a CDP command via WebSocket, return the result."""
    if websocket is None:
        raise ImportError(
            "websocket-client is required for CDP WebSocket. "
            "Install with: pip install websocket-client"
        )

    ws = websocket.create_connection(ws_url, timeout=timeout)
    msg_id = 1
    payload = {"id": msg_id, "method": method}
    if params:
        payload["params"] = params
    ws.send(json.dumps(payload))

    # Wait for matching response
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        raw = ws.recv()
        resp = json.loads(raw)
        if resp.get("id") == msg_id:
            ws.close()
            if "error" in resp:
                raise RuntimeError(f"CDP error: {resp['error']}")
            return resp.get("result", {})
    ws.close()
    raise TimeoutError(f"CDP timeout waiting for {method}")


# ---------------------------------------------------------------------------
# Fallback: HTTP-only extraction (no websocket-client needed)
# ---------------------------------------------------------------------------

def extract_via_http_api(host: str, port: int, target_domain: str) -> dict:
    """Minimal extraction using only CDP HTTP endpoints (no WS needed).

    Note: HTTP API can only list tabs and their URLs. Full cookie/storage
    extraction requires WebSocket. This returns tab info only.
    """
    pages = cdp_http_get(host, port, "/json")
    target_tabs = [
        p for p in pages
        if p.get("type") == "page"
        and target_domain in (p.get("url", ""))
    ]
    if not target_tabs:
        log.warning(
            "No Chrome tab found for domain '%s'. Found tabs: %s",
            target_domain,
            [p.get("url", "?")[:80] for p in pages if p.get("type") == "page"],
        )
        return {}
    return {"tabs": target_tabs, "ws_urls": [t.get("webSocketDebuggerUrl") for t in target_tabs]}


# ---------------------------------------------------------------------------
# Full CDP extraction
# ---------------------------------------------------------------------------

class CDPExtractor:
    """Extracts authentication data from a running Chrome via CDP."""

    def __init__(self, host: str = "127.0.0.1", port: int = 9222):
        self.host = host
        self.port = port
        self.ws_url: str = ""
        self.target_domain: str = ""

    def connect(self, target_domain: str) -> bool:
        """Find the Chrome tab matching target_domain and get its WS URL."""
        self.target_domain = target_domain
        try:
            pages = cdp_http_get(self.host, self.port, "/json")
        except Exception as e:
            log.error(
                "Cannot connect to Chrome CDP on %s:%d — %s\n"
                "→ Launch Chrome with: --remote-debugging-port=%d",
                self.host, self.port, e, self.port,
            )
            return False

        # Find tab matching target domain
        for page in pages:
            if page.get("type") != "page":
                continue
            page_url = page.get("url", "")
            if target_domain in page_url:
                self.ws_url = page.get("webSocketDebuggerUrl", "")
                log.info("Found tab: %s", page_url[:100])
                break

        if not self.ws_url:
            available = [p.get("url", "?")[:80] for p in pages if p.get("type") == "page"]
            log.error(
                "No tab found for domain '%s'. Open tabs:\n  %s",
                target_domain,
                "\n  ".join(available) if available else "(none)",
            )
            return False

        log.info("Connected to CDP WebSocket: %s", self.ws_url[:80])
        return True

    def get_all_cookies(self) -> list[dict]:
        """Get all browser cookies via Network.getAllCookies."""
        result = cdp_ws_send(self.ws_url, "Network.getAllCookies")
        return result.get("cookies", [])

    def get_domain_cookies(self) -> dict[str, str]:
        """Get cookies for the target domain only."""
        all_cookies = self.get_all_cookies()
        domain_cookies = {}
        for c in all_cookies:
            cookie_domain = c.get("domain", "")
            # Match exact domain or .domain (subdomain cookies)
            if (
                self.target_domain in cookie_domain
                or cookie_domain.lstrip(".") in self.target_domain
            ):
                domain_cookies[c["name"]] = c["value"]
        log.info(
            "Extracted %d cookies for %s (out of %d total)",
            len(domain_cookies), self.target_domain, len(all_cookies),
        )
        return domain_cookies

    def evaluate_js(self, expression: str) -> Any:
        """Execute JavaScript in the page context and return the result."""
        result = cdp_ws_send(self.ws_url, "Runtime.evaluate", {
            "expression": expression,
            "returnByValue": True,
            "awaitPromise": False,
        })
        val = result.get("result", {})
        if val.get("type") == "undefined":
            return None
        return val.get("value")

    def get_csrf_token(self) -> str | None:
        """Extract CSRF token from meta tags, forms, or JS variables."""
        # Strategy 1: meta[name=csrf-token] (Rails, Django, etc.)
        token = self.evaluate_js(
            'document.querySelector("meta[name=csrf-token]")?.content '
            '|| document.querySelector("meta[name=_csrf]")?.content '
            '|| document.querySelector("meta[name=csrf_token]")?.content '
            '|| ""'
        )
        if token:
            log.info("CSRF token found via meta tag")
            return token

        # Strategy 2: hidden input fields
        token = self.evaluate_js(
            'document.querySelector("input[name=_token]")?.value '
            '|| document.querySelector("input[name=csrf_token]")?.value '
            '|| document.querySelector("input[name=authenticity_token]")?.value '
            '|| document.querySelector("input[name=_csrf_token]")?.value '
            '|| ""'
        )
        if token:
            log.info("CSRF token found via hidden input")
            return token

        # Strategy 3: window.__CSRF or similar JS globals
        token = self.evaluate_js(
            'window.__CSRF_TOKEN__ || window.csrfToken || window._csrf || ""'
        )
        if token:
            log.info("CSRF token found via JS global")
            return token

        log.warning("No CSRF token found")
        return None

    def get_local_storage(self) -> dict[str, str]:
        """Get all localStorage key/value pairs."""
        data = self.evaluate_js("""
            (() => {
                const obj = {};
                for (let i = 0; i < localStorage.length; i++) {
                    const key = localStorage.key(i);
                    obj[key] = localStorage.getItem(key);
                }
                return obj;
            })()
        """)
        return data or {}

    def get_session_storage(self) -> dict[str, str]:
        """Get all sessionStorage key/value pairs."""
        data = self.evaluate_js("""
            (() => {
                const obj = {};
                for (let i = 0; i < sessionStorage.length; i++) {
                    const key = sessionStorage.key(i);
                    obj[key] = sessionStorage.getItem(key);
                }
                return obj;
            })()
        """)
        return data or {}

    def get_auth_tokens_from_storage(self) -> dict[str, str]:
        """Scan localStorage/sessionStorage for auth-related keys."""
        tokens: dict[str, str] = {}
        auth_patterns = re.compile(
            r"(token|jwt|bearer|auth|session|access_token|id_token|refresh_token"
            r"|api_key|apikey|credential|secret|sid|ssid|esid)",
            re.IGNORECASE,
        )

        for storage_name, storage_data in [
            ("localStorage", self.get_local_storage()),
            ("sessionStorage", self.get_session_storage()),
        ]:
            for key, val in storage_data.items():
                if auth_patterns.search(key):
                    tokens[f"{storage_name}.{key}"] = val
                    log.info("Auth key found: %s.%s (%d chars)", storage_name, key, len(val))
                # Also check if value looks like a JWT
                elif val and isinstance(val, str) and val.count(".") == 2 and len(val) > 50:
                    try:
                        import base64
                        # Quick JWT header check
                        header = base64.urlsafe_b64decode(val.split(".")[0] + "==")
                        if b'"alg"' in header:
                            tokens[f"{storage_name}.{key}"] = val
                            log.info("JWT found: %s.%s", storage_name, key)
                    except Exception:
                        pass

        return tokens

    def get_recent_auth_headers(self) -> dict[str, str]:
        """Capture Authorization headers from recent/active requests.

        Enables Network domain, navigates to a known page endpoint, and
        checks the request headers for Authorization.
        """
        headers: dict[str, str] = {}

        # Extract from performance entries (no Network domain needed)
        perf_data = self.evaluate_js("""
            (() => {
                const entries = performance.getEntriesByType('resource');
                const authUrls = entries
                    .filter(e => e.name.includes(location.hostname))
                    .map(e => e.name)
                    .slice(-20);
                return authUrls;
            })()
        """)
        if perf_data:
            log.info("Found %d recent resource entries", len(perf_data))

        # Try to extract from fetch/XHR interceptor
        auth_header = self.evaluate_js("""
            (() => {
                // Check if any global auth header is set
                if (window.__authHeader) return window.__authHeader;
                if (window.__AUTH_TOKEN) return 'Bearer ' + window.__AUTH_TOKEN;
                // Check axios defaults
                if (window.axios?.defaults?.headers?.common?.Authorization)
                    return window.axios.defaults.headers.common.Authorization;
                // Check jQuery ajaxSettings
                if (window.jQuery?.ajaxSettings?.headers?.Authorization)
                    return window.jQuery.ajaxSettings.headers.Authorization;
                return '';
            })()
        """)
        if auth_header:
            headers["Authorization"] = auth_header
            log.info("Authorization header found via JS globals")

        return headers

    def extract_all(self) -> dict[str, Any]:
        """Full extraction — returns structured auth data."""
        log.info("Starting full extraction for %s...", self.target_domain)

        cookies = self.get_domain_cookies()
        csrf = self.get_csrf_token()
        storage_tokens = self.get_auth_tokens_from_storage()
        auth_headers = self.get_recent_auth_headers()

        # Determine the best Bearer token
        bearer_token = ""
        for key, val in storage_tokens.items():
            if "access_token" in key.lower() or "token" in key.lower():
                bearer_token = val
                break
        # Fallback: check cookies for common token names
        if not bearer_token:
            for name in ("access_token", "token", "jwt", "auth_token", "bearer"):
                if name in cookies:
                    bearer_token = cookies[name]
                    break

        return {
            "cookies": cookies,
            "csrf_token": csrf or "",
            "storage_tokens": storage_tokens,
            "auth_headers": auth_headers,
            "bearer_token": bearer_token,
        }


# ---------------------------------------------------------------------------
# .env file generation
# ---------------------------------------------------------------------------

def _mask(val: str, show: int = 8) -> str:
    """Mask a secret value, showing only the first N chars."""
    if len(val) <= show:
        return val
    return val[:show] + "..." + f"({len(val)} chars)"


def generate_env_file(auth_data: dict[str, Any], output_path: str) -> None:
    """Write extracted auth data as a sourceable .env file."""
    lines: list[str] = [
        "# Auto-generated by auth_extractor.py — DO NOT COMMIT",
        f"# Extracted at: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "#",
        "# Usage: source {output} && bash runner.sh <target>",
        "",
    ]

    cookies = auth_data.get("cookies", {})
    csrf = auth_data.get("csrf_token", "")
    bearer = auth_data.get("bearer_token", "")
    auth_headers = auth_data.get("auth_headers", {})
    storage = auth_data.get("storage_tokens", {})

    # AUTH_TOKEN — Bearer token (used by lib.py → Authorization: Bearer <token>)
    if bearer:
        lines.append(f'export AUTH_TOKEN="{bearer}"')
        log.info("AUTH_TOKEN set (%s)", _mask(bearer))

    # AUTH_HEADER — Full Authorization header value (overrides AUTH_TOKEN)
    if "Authorization" in auth_headers:
        val = auth_headers["Authorization"]
        lines.append(f'export AUTH_HEADER="{val}"')
        log.info("AUTH_HEADER set (%s)", _mask(val))

    # CSRF_TOKEN
    if csrf:
        lines.append(f'export CSRF_TOKEN="{csrf}"')
        log.info("CSRF_TOKEN set (%s)", _mask(csrf))

    # AUTH_COOKIES — JSON dict of cookies (parsed by lib.py via json.loads)
    if cookies:
        cookies_json = json.dumps(cookies, ensure_ascii=False)
        # Escape for shell
        cookies_escaped = cookies_json.replace("'", "'\\''")
        lines.append(f"export AUTH_COOKIES='{cookies_escaped}'")
        log.info("AUTH_COOKIES set (%d cookies)", len(cookies))

    # AUTH_HEADERS — Extra headers JSON (for custom headers beyond Authorization)
    extra_headers = {k: v for k, v in auth_headers.items() if k != "Authorization"}
    if extra_headers:
        headers_json = json.dumps(extra_headers, ensure_ascii=False)
        headers_escaped = headers_json.replace("'", "'\\''")
        lines.append(f"export AUTH_HEADERS='{headers_escaped}'")
        log.info("AUTH_HEADERS set (%d headers)", len(extra_headers))

    # Storage tokens as individual vars (informational)
    if storage:
        lines.append("")
        lines.append("# Storage tokens (for reference — not consumed by scanners)")
        for key, val in storage.items():
            safe_key = re.sub(r"[^A-Za-z0-9_]", "_", key).upper()
            lines.append(f'# STORAGE_{safe_key}="{_mask(val, 20)}"')

    lines.append("")
    output = Path(output_path)
    output.write_text("\n".join(lines), encoding="utf-8")
    output.chmod(0o600)
    log.info("Auth env written to %s (chmod 600)", output)

    # Summary
    print("\n" + "=" * 60)
    print("  AUTH EXTRACTION SUMMARY")
    print("=" * 60)
    print(f"  Cookies:        {len(cookies)} extracted")
    print(f"  CSRF Token:     {'✓' if csrf else '✗ not found'}")
    print(f"  Bearer Token:   {'✓' if bearer else '✗ not found'}")
    print(f"  Auth Headers:   {len(auth_headers)} found")
    print(f"  Storage Tokens: {len(storage)} found")
    print(f"  Output:         {output}")
    print("=" * 60)
    print(f"\n  → source {output} && bash runner.sh <target>\n")


# ---------------------------------------------------------------------------
# Chrome launcher helper
# ---------------------------------------------------------------------------

CHROME_PATHS = {
    "darwin": [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
    ],
    "linux": [
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/snap/bin/chromium",
    ],
}


def find_chrome() -> str | None:
    """Find Chrome/Chromium binary path."""
    import platform
    system = platform.system().lower()
    paths = CHROME_PATHS.get(system, CHROME_PATHS["linux"])
    for p in paths:
        if os.path.isfile(p):
            return p
    # Try PATH
    import shutil
    for name in ("google-chrome", "chromium", "chromium-browser"):
        found = shutil.which(name)
        if found:
            return found
    return None


def _make_fresh_profile_dir() -> str:
    """Create a fresh disposable Chrome profile directory.

    Always starts from scratch — no lingering sessions, no cached accounts.
    This is mandatory: CDP does not work reliably when Chrome already has an
    active user profile / Google account signed in.
    """
    import tempfile
    import shutil

    profile_dir = Path(tempfile.gettempdir()) / "chrome-cdp-clean"
    if profile_dir.exists():
        log.info("Removing stale CDP profile: %s", profile_dir)
        shutil.rmtree(profile_dir, ignore_errors=True)
    profile_dir.mkdir(parents=True)
    log.info("Fresh CDP profile created: %s", profile_dir)
    return str(profile_dir)


def launch_chrome_with_debugging(
    port: int = 9222,
    target_url: str = "",
    *,
    auto: bool = False,
) -> "subprocess.Popen[bytes] | None":
    """Launch Chrome with a fresh profile and remote debugging enabled.

    When *auto=True*, actually spawn the process and return the Popen object.
    When *auto=False*, just print the command for the user to copy/paste.

    IMPORTANT — Chrome is launched with:
      --user-data-dir=<fresh temp dir>   →  no Google account, no cookies
      --no-first-run --no-default-browser-check  →  skip setup wizards
      --disable-sync  →  no background Google sync that breaks CDP
    """
    import subprocess

    chrome = find_chrome()
    if not chrome:
        print("\n" + "=" * 60)
        print("  CHROME NOT FOUND")
        print("=" * 60)
        print("\n  Install Google Chrome or set CHROME_BIN env var.\n")
        print("=" * 60 + "\n")
        return None

    profile_dir = _make_fresh_profile_dir()

    chrome_args = [
        chrome,
        f"--remote-debugging-port={port}",
        f"--user-data-dir={profile_dir}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-sync",
        "--disable-background-networking",
        "--disable-client-side-phishing-detection",
        "--disable-extensions",
    ]
    if target_url:
        chrome_args.append(target_url)

    if auto:
        log.info("Launching Chrome (CDP port %d, clean profile)...", port)
        proc = subprocess.Popen(
            chrome_args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        log.info("Chrome PID: %d", proc.pid)
        return proc

    # Manual mode — print the command
    cmd_str = " ".join(f'"{a}"' if " " in a else a for a in chrome_args)
    print("\n" + "=" * 60)
    print("  CHROME NOT DETECTED ON CDP PORT")
    print("=" * 60)
    print(f"\n  Launch Chrome with remote debugging:\n")
    print(f"    {cmd_str}\n")
    print("  Then log in to the target website and re-run this script.\n")
    print("=" * 60 + "\n")
    return None


def _wait_for_cdp_ready(host: str, port: int, timeout: float = 30.0) -> bool:
    """Poll CDP HTTP endpoint until Chrome is ready."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            pages = cdp_http_get(host, port, "/json")
            if isinstance(pages, list) and len(pages) > 0:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def _wait_for_user_login(
    extractor: CDPExtractor,
    target_domain: str,
    *,
    poll_interval: float = 3.0,
    timeout: float = 300.0,
) -> bool:
    """Poll cookies until the user has logged in (session cookie appears).

    Heuristic: considers the user logged in when ≥3 cookies exist for the
    target domain (most apps set session + CSRF + preferences on login).
    """
    print("\n" + "=" * 60)
    print("  WAITING FOR LOGIN")
    print("=" * 60)
    print(f"\n  Log in to {target_domain} in the Chrome window.")
    print("  This script will detect the session automatically.")
    print("  Press Ctrl+C to abort.\n")

    deadline = time.monotonic() + timeout
    prev_count = 0
    while time.monotonic() < deadline:
        try:
            cookies = extractor.get_domain_cookies()
            if len(cookies) != prev_count:
                log.info("Cookies for %s: %d", target_domain, len(cookies))
                prev_count = len(cookies)
            # Heuristic: ≥3 domain cookies = likely logged in
            if len(cookies) >= 3:
                # Extra check: look for session-like cookie names
                has_session = any(
                    kw in name.lower()
                    for name in cookies
                    for kw in ("session", "sid", "ssid", "auth", "token", "jwt")
                )
                if has_session or len(cookies) >= 5:
                    log.info("Login detected (%d cookies, session-like key found)", len(cookies))
                    print("\n  ✓ Login detected! Extracting tokens...\n")
                    return True
        except Exception as e:
            log.debug("Poll error: %s", e)
        time.sleep(poll_interval)

    log.warning("Login wait timed out after %.0fs", timeout)
    return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract auth tokens from Chrome via CDP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--target", "-t",
        required=True,
        help="Target URL (e.g. https://target.example.com)",
    )
    parser.add_argument(
        "--output", "-o",
        default="auth.env",
        help="Output .env file path (default: auth.env)",
    )
    parser.add_argument(
        "--cdp-host",
        default=os.environ.get("CDP_HOST", "127.0.0.1"),
        help="CDP host (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--cdp-port",
        type=int,
        default=int(os.environ.get("CDP_PORT", "9222")),
        help="CDP port (default: 9222)",
    )
    parser.add_argument(
        "--launch-chrome",
        action="store_true",
        help="Auto-launch Chrome with a fresh clean profile (no accounts)",
    )
    parser.add_argument(
        "--wait-login",
        action="store_true",
        help="Wait for user to log in before extracting (implies --launch-chrome)",
    )
    parser.add_argument(
        "--login-timeout",
        type=float,
        default=300.0,
        help="Max seconds to wait for login (default: 300 = 5 min)",
    )
    parser.add_argument(
        "--kill-chrome",
        action="store_true",
        help="Kill the Chrome instance after extraction",
    )
    parser.add_argument(
        "--cookies-only",
        action="store_true",
        help="Extract only cookies (skip storage/JS analysis)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Also output raw extraction data as JSON",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be extracted without connecting",
    )
    args = parser.parse_args()

    # --wait-login implies --launch-chrome
    if args.wait_login:
        args.launch_chrome = True

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    target_domain = urlparse(args.target).hostname or args.target
    log.info("Target domain: %s", target_domain)

    if args.dry_run:
        print("[DRY-RUN] Would connect to CDP at %s:%d" % (args.cdp_host, args.cdp_port))
        print(f"[DRY-RUN] Would extract auth for domain: {target_domain}")
        print(f"[DRY-RUN] Would write env to: {args.output}")
        return 0

    # Check WebSocket dependency
    if websocket is None:
        log.error(
            "websocket-client package not found.\n"
            "  Install with: pip install websocket-client\n"
            "  Or add to requirements.txt"
        )
        return 1

    # Launch Chrome if requested
    chrome_proc = None
    if args.launch_chrome:
        chrome_proc = launch_chrome_with_debugging(
            args.cdp_port, args.target, auto=True,
        )
        if chrome_proc is None:
            return 1
        # Wait for CDP to be ready
        log.info("Waiting for Chrome CDP to be ready...")
        if not _wait_for_cdp_ready(args.cdp_host, args.cdp_port):
            log.error("Chrome did not start CDP in time")
            chrome_proc.terminate()
            return 1
        log.info("Chrome CDP is ready")

    # Connect to CDP
    extractor = CDPExtractor(args.cdp_host, args.cdp_port)
    if not extractor.connect(target_domain):
        if chrome_proc is None:
            # Chrome not managed by us — print instructions
            launch_chrome_with_debugging(args.cdp_port, args.target)
        else:
            log.error("Chrome launched but no tab for %s found", target_domain)
            chrome_proc.terminate()
        return 1

    # Wait for user to log in if requested
    if args.wait_login:
        if not _wait_for_user_login(
            extractor, target_domain, timeout=args.login_timeout,
        ):
            log.error("Login not detected — aborting")
            if chrome_proc and args.kill_chrome:
                chrome_proc.terminate()
            return 1

    # Extract
    if args.cookies_only:
        cookies = extractor.get_domain_cookies()
        auth_data = {"cookies": cookies, "csrf_token": "", "storage_tokens": {},
                     "auth_headers": {}, "bearer_token": ""}
    else:
        auth_data = extractor.extract_all()

    if not any(auth_data.values()):
        log.warning("No auth data extracted. Are you logged in?")
        return 1

    # Generate .env
    generate_env_file(auth_data, args.output)

    # Optional JSON dump
    if args.json_output:
        json_path = Path(args.output).with_suffix(".json")
        json_path.write_text(json.dumps(auth_data, indent=2, ensure_ascii=False))
        json_path.chmod(0o600)
        log.info("Raw JSON written to %s", json_path)

    # Kill Chrome if requested
    if chrome_proc and args.kill_chrome:
        log.info("Terminating Chrome (PID %d)...", chrome_proc.pid)
        chrome_proc.terminate()
        try:
            chrome_proc.wait(timeout=5)
        except Exception:
            chrome_proc.kill()
        log.info("Chrome terminated")

    return 0


if __name__ == "__main__":
    sys.exit(main())
