"""DAG configuration — parallel groups, retries, tool metadata."""

from __future__ import annotations

RETRY_DEFAULTS = {
    "max_retries": 2,
    "retry_delay_seconds": 10,
    "retry_jitter_factor": 0.5,
}

# ---------------------------------------------------------------------------
# Parallel groups: tools in the same group run concurrently.
# Groups execute in dependency order (group N waits for group N-1).
# ---------------------------------------------------------------------------
PARALLEL_GROUPS: list[dict] = [
    # ── Group 0: Recon (no dependencies) ──────────────────────────
    {
        "name": "recon",
        "tools": [
            "subfinder", "httpx", "naabu", "katana", "amass",
            "dnsx", "whatweb", "wafw00f", "gowitness",
        ],
        "depends_on": [],
    },
    # ── Group 1: DAST + Audit (after recon for live hosts / endpoints) ──
    {
        "name": "dast",
        "tools": [
            "nuclei", "zap", "nikto", "testssl", "corscanner",
            "nmap", "dalfox", "log4j-scan",
        ],
        "depends_on": ["recon"],
    },
    # ── Group 2: Injection / Fuzzing (after DAST for discovered endpoints) ──
    {
        "name": "injection",
        "tools": [
            "sqlmap", "sstimap", "crlfuzz", "ffuf", "feroxbuster",
            "arjun", "ssrfmap", "ppmap",
        ],
        "depends_on": ["dast"],
    },
    # ── Group 3: Specialized scans (independent of injection results) ──
    {
        "name": "specialized",
        "tools": [
            "graphw00f", "clairvoyance", "jsluice", "cloud-enum",
            "dnsreaper", "subdominator", "cmseek", "theharvester",
            "cherrybomb", "interactsh",
        ],
        "depends_on": ["recon"],
    },
    # ── Group 4: Python custom scanners ───────────────────────────
    {
        "name": "python-scanners",
        "tools": [
            "idor-scanner", "auth-bypass", "user-enum", "notif-inject",
            "redirect-cors", "oidc-audit", "bypass-403-advanced",
            "ssrf-scanner", "xss-scanner", "api-discovery", "secret-leak",
            "websocket-scanner", "cache-deception", "slowloris-check",
        ],
        "depends_on": ["recon"],
    },
    # ── Group 5: Code / Image / Binary (no web deps, can run early) ──
    {
        "name": "code-analysis",
        "tools": [
            "semgrep", "gitleaks", "trufflehog", "trivy",
            "dependency-check", "trivy-image", "cwe-checker",
            "cve-bin-tool", "dockle", "retirejs",
        ],
        "depends_on": [],
    },
    # ── Group 6: LLM / JWT / Auth (conditional, special env) ──────
    {
        "name": "conditional",
        "tools": ["garak", "jwt-tool"],
        "depends_on": [],
    },
    # ── Group 7: WAF bypass (after WAF detection) ─────────────────
    {
        "name": "waf-bypass",
        "tools": ["bypass-403"],
        "depends_on": ["recon"],
    },
    # ── Group 8: Web advanced — smuggling, cache deception ────────
    {
        "name": "web-advanced",
        "tools": ["smuggler"],
        "depends_on": ["dast"],
    },
    # ── Group 9: IaC / Cloud security scanning ────────────────────
    {
        "name": "iac",
        "tools": ["checkov"],
        "depends_on": [],
    },
    # ── Group 10: API fuzzing (needs OpenAPI spec) ────────────────
    {
        "name": "api-fuzzing",
        "tools": ["restler"],
        "depends_on": ["recon"],
    },
]

# ---------------------------------------------------------------------------
# Tool metadata — profile, condition, extra docker-compose args
# ---------------------------------------------------------------------------
TOOL_META: dict[str, dict] = {
    # name → {profile, requires, env_requires, file_requires}
    "subfinder":            {"profile": None,               "requires": "domain"},
    "httpx":                {"profile": "recon",            "requires": "domain"},
    "naabu":                {"profile": "recon",            "requires": "domain"},
    "katana":               {"profile": "recon",            "requires": "target"},
    "amass":                {"profile": None,               "requires": "domain"},
    "dnsx":                 {"profile": None,               "requires": "domain"},
    "whatweb":              {"profile": None,               "requires": "target"},
    "wafw00f":              {"profile": None,               "requires": "target"},
    "gowitness":            {"profile": "screenshot",       "requires": "target"},
    "nuclei":               {"profile": None,               "requires": "target"},
    "nuclei-full":          {"profile": None,               "requires": "target", "flag": "full"},
    "zap":                  {"profile": None,               "requires": "target"},
    "zap-full":             {"profile": None,               "requires": "target", "flag": "full"},
    "nikto":                {"profile": None,               "requires": "target"},
    "testssl":              {"profile": None,               "requires": "target"},
    "corscanner":           {"profile": None,               "requires": "domain"},
    "nmap":                 {"profile": "network",          "requires": "domain"},
    "dalfox":               {"profile": "xss",              "requires": "target"},
    "log4j-scan":           {"profile": None,               "requires": "target"},
    "sqlmap":               {"profile": None,               "requires": "target", "sequential": True},
    "sstimap":              {"profile": None,               "requires": "target"},
    "crlfuzz":              {"profile": None,               "requires": "target"},
    "ffuf":                 {"profile": "fuzz",             "requires": "target"},
    "feroxbuster":          {"profile": "fuzz",             "requires": "target"},
    "arjun":                {"profile": "fuzz",             "requires": "target"},
    "ssrfmap":              {"profile": "ssrf",             "requires": "target"},
    "ppmap":                {"profile": "prototype",        "requires": "target"},
    "graphw00f":            {"profile": None,               "requires": "target"},
    "clairvoyance":         {"profile": "graphql",          "requires": "target"},
    "jsluice":              {"profile": "js",               "requires": "target"},
    "cloud-enum":           {"profile": None,               "requires": "domain"},
    "dnsreaper":            {"profile": None,               "requires": "domain"},
    "subdominator":         {"profile": None,               "requires": "domain"},
    "cmseek":               {"profile": "cms",              "requires": "target"},
    "theharvester":         {"profile": "osint",            "requires": "domain"},
    "cherrybomb":           {"profile": "openapi",          "requires": None, "file_requires": "reports/cherrybomb/openapi.json"},
    "interactsh":           {"profile": "oob",              "requires": None},
    "semgrep":              {"profile": None,               "requires": "code"},
    "gitleaks":             {"profile": None,               "requires": "repo"},
    "trufflehog":           {"profile": None,               "requires": "repo"},
    "trivy":                {"profile": None,               "requires": "code"},
    "dependency-check":     {"profile": None,               "requires": "code"},
    "trivy-image":          {"profile": None,               "requires": "image"},
    "cwe-checker":          {"profile": None,               "requires": "binary"},
    "cve-bin-tool":         {"profile": None,               "requires": "bin_dir"},
    "dockle":               {"profile": "container",        "requires": "image"},
    "retirejs":             {"profile": "frontend-sca",     "requires": "code"},
    "garak":                {"profile": None,               "requires": None, "env_requires": ["OPENAI_API_KEY", "ANTHROPIC_API_KEY"]},
    "jwt-tool":             {"profile": "jwt",              "requires": None, "env_requires": ["JWT_TOKEN"]},
    "bypass-403":           {"profile": "waf",              "requires": "target"},
    # Python custom scanners — all share the python-scanners profile
    "idor-scanner":         {"profile": "python-scanners",  "requires": "target"},
    "auth-bypass":          {"profile": "python-scanners",  "requires": "target"},
    "user-enum":            {"profile": "python-scanners",  "requires": "target"},
    "notif-inject":         {"profile": "python-scanners",  "requires": "target"},
    "redirect-cors":        {"profile": "python-scanners",  "requires": "target"},
    "oidc-audit":           {"profile": "python-scanners",  "requires": "target"},
    "bypass-403-advanced":  {"profile": "python-scanners",  "requires": "target"},
    "ssrf-scanner":         {"profile": "python-scanners",  "requires": "target"},
    "xss-scanner":          {"profile": "python-scanners",  "requires": "target"},
    "api-discovery":        {"profile": "python-scanners",  "requires": "target"},
    "secret-leak":          {"profile": "python-scanners",  "requires": "target"},
    "websocket-scanner":    {"profile": "python-scanners",  "requires": "target"},
    "cache-deception":      {"profile": "python-scanners",  "requires": "target"},
    "slowloris-check":      {"profile": "python-scanners",  "requires": "target"},
    # Phase 3 — new tools
    "smuggler":             {"profile": "web-advanced",     "requires": "target"},
    "checkov":              {"profile": "iac",              "requires": "code"},
    "restler":              {"profile": "api-fuzzing",      "requires": None, "file_requires": "configs/openapi.yaml"},
}

# CWE → downstream tool routing (conditional triggers)
CWE_TRIGGERS: dict[str, list[str]] = {
    "CWE-918": ["ssrf-scanner"],      # SSRF found → deep SSRF scan
    "CWE-79":  ["xss-scanner"],       # XSS found → deep XSS scan
    "CWE-89":  ["sqlmap"],            # SQLi found → SQLMap confirmation
    "CWE-444": ["smuggler"],          # Smuggling indicators → deep smuggling test
    "CWE-524": ["cache-deception"],   # Cache issues → cache deception test
    "CWE-400": ["slowloris-check"],   # Resource issues → slowloris detection
    "CWE-284": ["websocket-scanner"], # Access control → websocket auth check
}

# Tools that produce endpoints for downstream injection
ENDPOINT_PRODUCERS = ["api-discovery", "katana", "ffuf", "feroxbuster"]
