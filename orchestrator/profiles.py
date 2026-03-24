"""Scan profiles — light / medium / full tool sets."""

# ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.

# Light: 15 essential tools, ~3 GB RAM, <10 min
LIGHT_TOOLS: list[str] = [
    # DAST core
    "nuclei",
    "zap-baseline",
    "testssl",
    # Injection
    "sqlmap",
    # SAST / Secrets
    "semgrep",
    "gitleaks",
    "trivy",
    # Python scanners (5 most impactful)
    "idor-scanner",
    "auth-bypass",
    "secret-leak",
    "api-discovery",
    "xss-scanner",
    # Recon (minimal)
    "httpx",
    "whatweb",
    "wafw00f",
]

# Medium: ~30 tools, light + recon + fuzzing + specialized
MEDIUM_TOOLS: list[str] = LIGHT_TOOLS + [
    # Recon
    "subfinder",
    "katana",
    "amass",
    "dnsx",
    "gowitness",
    # Injection / Fuzzing
    "sstimap",
    "crlfuzz",
    "ffuf",
    "feroxbuster",
    "arjun",
    # DAST extended
    "nikto",
    "corscanner",
    "log4j-scan",
    # Secrets
    "trufflehog",
    # Python scanners (remaining)
    "user-enum",
    "redirect-cors",
    "oidc-audit",
    "bypass-403-advanced",
    "ssrf-scanner",
    "websocket-scanner",
    "cache-deception",
]

# Full: all tools (no --only filter)
FULL_TOOLS: list[str] = []  # empty = no filter → run everything


def get_profile_tools(profile: str) -> list[str]:
    """Return tool list for the given profile name."""
    profiles = {
        "light": LIGHT_TOOLS,
        "medium": MEDIUM_TOOLS,
        "full": FULL_TOOLS,
    }
    return profiles.get(profile, FULL_TOOLS)
