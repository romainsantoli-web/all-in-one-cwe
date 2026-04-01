#!/usr/bin/env python3
"""Bug chaining rules database — known escalation paths between CWEs.

Each rule defines a trigger CWE, the next steps to confirm escalation,
the final impact, and the typical bug bounty payout range.

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

CHAIN_RULES: list[dict] = [
    # ── SSRF chains ───────────────────────────────────────
    {
        "id": "SSRF→METADATA→RCE",
        "trigger_cwe": "CWE-918",
        "next_steps": [
            {"action": "test_cloud_metadata", "tools": ["ssrf-scanner"],
             "payloads": ["http://169.254.169.254/latest/meta-data/"],
             "escalates_to": "CWE-200"},
            {"action": "exfil_iam_credentials", "tools": ["ssrf-scanner"],
             "escalates_to": "CWE-522"},
        ],
        "final_impact": "Remote Code Execution via cloud credential theft",
        "severity": "critical",
        "typical_payout": "$1K-$15K",
    },
    {
        "id": "SSRF→INTERNAL_SCAN→DATA",
        "trigger_cwe": "CWE-918",
        "next_steps": [
            {"action": "scan_internal_ports", "tools": ["ssrf-scanner"],
             "payloads": ["http://127.0.0.1:6379/", "http://127.0.0.1:9200/"],
             "escalates_to": "CWE-441"},
        ],
        "final_impact": "Internal service access (Redis, Elasticsearch, etc.)",
        "severity": "high",
        "typical_payout": "$500-$5K",
    },
    # ── XSS chains ────────────────────────────────────────
    {
        "id": "XSS→CSRF→ATO",
        "trigger_cwe": "CWE-79",
        "next_steps": [
            {"action": "check_httponly_cookie", "tools": ["header-classifier"],
             "escalates_to": "CWE-1004"},
            {"action": "test_csrf_on_sensitive", "tools": ["xss-scanner"],
             "escalates_to": "CWE-352"},
        ],
        "final_impact": "Account Takeover via session hijack + CSRF combo",
        "severity": "critical",
        "typical_payout": "$500-$5K",
    },
    {
        "id": "XSS→TOKEN_THEFT→API_ABUSE",
        "trigger_cwe": "CWE-79",
        "next_steps": [
            {"action": "extract_jwt_from_dom", "tools": ["xss-scanner"],
             "escalates_to": "CWE-522"},
            {"action": "call_admin_api", "tools": ["api-discovery"],
             "escalates_to": "CWE-269"},
        ],
        "final_impact": "Privilege escalation via stolen JWT / API keys",
        "severity": "critical",
        "typical_payout": "$1K-$10K",
    },
    {
        "id": "STORED_XSS→ADMIN_ATO",
        "trigger_cwe": "CWE-79",
        "next_steps": [
            {"action": "inject_stored_payload", "tools": ["xss-scanner"],
             "escalates_to": "CWE-79"},
            {"action": "wait_admin_trigger", "tools": [],
             "escalates_to": "CWE-287"},
        ],
        "final_impact": "Admin account takeover via stored XSS trojan",
        "severity": "critical",
        "typical_payout": "$2K-$15K",
    },
    # ── IDOR chains ───────────────────────────────────────
    {
        "id": "IDOR→PII→GDPR",
        "trigger_cwe": "CWE-639",
        "next_steps": [
            {"action": "enumerate_user_ids", "tools": ["idor-scanner"],
             "escalates_to": "CWE-200"},
            {"action": "extract_pii", "tools": ["idor-scanner"],
             "escalates_to": "CWE-359"},
        ],
        "final_impact": "Mass PII leakage — GDPR violation potential",
        "severity": "critical",
        "typical_payout": "$1K-$10K",
    },
    {
        "id": "IDOR→ADMIN_ACCESS",
        "trigger_cwe": "CWE-639",
        "next_steps": [
            {"action": "access_admin_objects", "tools": ["idor-scanner", "auth-bypass"],
             "escalates_to": "CWE-269"},
        ],
        "final_impact": "Vertical privilege escalation via IDOR to admin resources",
        "severity": "critical",
        "typical_payout": "$1K-$8K",
    },
    # ── SQLi chains ───────────────────────────────────────
    {
        "id": "SQLI→DATA_EXFIL",
        "trigger_cwe": "CWE-89",
        "next_steps": [
            {"action": "extract_tables", "tools": ["sqlmap"],
             "escalates_to": "CWE-200"},
            {"action": "dump_credentials", "tools": ["sqlmap"],
             "escalates_to": "CWE-522"},
        ],
        "final_impact": "Full database compromise — credential + data exfiltration",
        "severity": "critical",
        "typical_payout": "$3K-$30K",
    },
    {
        "id": "SQLI→RCE",
        "trigger_cwe": "CWE-89",
        "next_steps": [
            {"action": "stacked_queries_test", "tools": ["sqlmap"],
             "escalates_to": "CWE-78"},
            {"action": "file_write_webshell", "tools": ["sqlmap"],
             "escalates_to": "CWE-434"},
        ],
        "final_impact": "Remote Code Execution via SQL injection + file write",
        "severity": "critical",
        "typical_payout": "$5K-$50K",
    },
    # ── SSTI chains ───────────────────────────────────────
    {
        "id": "SSTI→RCE",
        "trigger_cwe": "CWE-1336",
        "next_steps": [
            {"action": "confirm_code_exec", "tools": ["sstimap"],
             "payloads": ["{{7*7}}", "${7*7}", "<%=7*7%>"],
             "escalates_to": "CWE-94"},
            {"action": "reverse_shell", "tools": ["sstimap"],
             "escalates_to": "CWE-78"},
        ],
        "final_impact": "Remote Code Execution via template engine exploitation",
        "severity": "critical",
        "typical_payout": "$5K-$30K",
    },
    # ── Open Redirect chains ──────────────────────────────
    {
        "id": "REDIRECT→OAUTH_THEFT",
        "trigger_cwe": "CWE-601",
        "next_steps": [
            {"action": "chain_with_oauth_callback", "tools": ["redirect-cors", "oidc-audit"],
             "escalates_to": "CWE-287"},
        ],
        "final_impact": "OAuth token theft via redirect to attacker-controlled callback",
        "severity": "high",
        "typical_payout": "$500-$5K",
    },
    {
        "id": "REDIRECT→PHISHING",
        "trigger_cwe": "CWE-601",
        "next_steps": [
            {"action": "craft_phishing_landing", "tools": [],
             "escalates_to": "CWE-451"},
        ],
        "final_impact": "Credential phishing via trusted domain redirect",
        "severity": "medium",
        "typical_payout": "$100-$500",
    },
    # ── Auth bypass chains ────────────────────────────────
    {
        "id": "AUTH_BYPASS→ADMIN→DATA",
        "trigger_cwe": "CWE-287",
        "next_steps": [
            {"action": "access_admin_panel", "tools": ["auth-bypass", "bypass-403-advanced"],
             "escalates_to": "CWE-269"},
            {"action": "exfil_admin_data", "tools": ["api-discovery"],
             "escalates_to": "CWE-200"},
        ],
        "final_impact": "Full admin access → data exfiltration",
        "severity": "critical",
        "typical_payout": "$3K-$20K",
    },
    {
        "id": "AUTH_BYPASS→ACCOUNT_CREATION",
        "trigger_cwe": "CWE-287",
        "next_steps": [
            {"action": "create_rogue_admin", "tools": ["auth-bypass"],
             "escalates_to": "CWE-269"},
        ],
        "final_impact": "Persistent access via rogue admin account creation",
        "severity": "critical",
        "typical_payout": "$2K-$15K",
    },
    # ── Path traversal chains ─────────────────────────────
    {
        "id": "PATH_TRAVERSAL→SOURCE_LEAK",
        "trigger_cwe": "CWE-22",
        "next_steps": [
            {"action": "read_source_code", "tools": ["ffuf", "feroxbuster"],
             "payloads": ["..%2f..%2f..%2fetc/passwd", "....//....//etc/hostname"],
             "escalates_to": "CWE-200"},
            {"action": "extract_secrets_from_source", "tools": ["gitleaks", "trufflehog"],
             "escalates_to": "CWE-798"},
        ],
        "final_impact": "Source code leak → hardcoded credentials extraction",
        "severity": "critical",
        "typical_payout": "$1K-$10K",
    },
    {
        "id": "PATH_TRAVERSAL→FILE_WRITE→RCE",
        "trigger_cwe": "CWE-22",
        "next_steps": [
            {"action": "test_file_write", "tools": [],
             "escalates_to": "CWE-434"},
            {"action": "upload_webshell", "tools": [],
             "escalates_to": "CWE-78"},
        ],
        "final_impact": "RCE via arbitrary file write + webshell",
        "severity": "critical",
        "typical_payout": "$5K-$30K",
    },
    # ── CSRF chains ───────────────────────────────────────
    {
        "id": "CSRF→PASSWORD_CHANGE→ATO",
        "trigger_cwe": "CWE-352",
        "next_steps": [
            {"action": "csrf_password_change", "tools": ["xss-scanner"],
             "escalates_to": "CWE-620"},
        ],
        "final_impact": "Account Takeover via CSRF on password change endpoint",
        "severity": "high",
        "typical_payout": "$500-$5K",
    },
    {
        "id": "CSRF→EMAIL_CHANGE→ATO",
        "trigger_cwe": "CWE-352",
        "next_steps": [
            {"action": "csrf_email_change", "tools": ["xss-scanner"],
             "escalates_to": "CWE-620"},
            {"action": "password_reset_to_new_email", "tools": [],
             "escalates_to": "CWE-287"},
        ],
        "final_impact": "Account Takeover via CSRF email change → password reset",
        "severity": "high",
        "typical_payout": "$500-$5K",
    },
    # ── CORS chains ───────────────────────────────────────
    {
        "id": "CORS→DATA_THEFT",
        "trigger_cwe": "CWE-942",
        "next_steps": [
            {"action": "cross_origin_data_read", "tools": ["corscanner", "redirect-cors"],
             "escalates_to": "CWE-200"},
        ],
        "final_impact": "Cross-origin data theft from authenticated sessions",
        "severity": "high",
        "typical_payout": "$500-$3K",
    },
    # ── Deserialization chains ────────────────────────────
    {
        "id": "DESER→RCE",
        "trigger_cwe": "CWE-502",
        "next_steps": [
            {"action": "craft_gadget_chain", "tools": [],
             "escalates_to": "CWE-94"},
            {"action": "reverse_shell", "tools": [],
             "escalates_to": "CWE-78"},
        ],
        "final_impact": "Remote Code Execution via deserialization gadget chain",
        "severity": "critical",
        "typical_payout": "$5K-$30K",
    },
    # ── HTTP Request Smuggling chains ─────────────────────
    {
        "id": "SMUGGLING→CACHE_POISON",
        "trigger_cwe": "CWE-444",
        "next_steps": [
            {"action": "poison_cache_entry", "tools": ["cache-deception"],
             "escalates_to": "CWE-345"},
        ],
        "final_impact": "Cache poisoning — serve malicious content to all users",
        "severity": "critical",
        "typical_payout": "$3K-$15K",
    },
    {
        "id": "SMUGGLING→REQUEST_HIJACK",
        "trigger_cwe": "CWE-444",
        "next_steps": [
            {"action": "hijack_next_request", "tools": [],
             "escalates_to": "CWE-294"},
        ],
        "final_impact": "Hijack authenticated requests from other users",
        "severity": "critical",
        "typical_payout": "$3K-$20K",
    },
    # ── Secret exposure chains ────────────────────────────
    {
        "id": "SECRET→LATERAL_MOVEMENT",
        "trigger_cwe": "CWE-798",
        "next_steps": [
            {"action": "test_leaked_creds", "tools": ["gitleaks", "trufflehog"],
             "escalates_to": "CWE-287"},
            {"action": "access_cloud_services", "tools": [],
             "escalates_to": "CWE-269"},
        ],
        "final_impact": "Lateral movement via hardcoded credentials / API keys",
        "severity": "critical",
        "typical_payout": "$1K-$10K",
    },
    # ── Cache deception chains ────────────────────────────
    {
        "id": "CACHE_DECEPTION→SESSION_STEAL",
        "trigger_cwe": "CWE-525",
        "next_steps": [
            {"action": "cache_authenticated_page", "tools": ["cache-deception"],
             "escalates_to": "CWE-200"},
        ],
        "final_impact": "Steal authenticated responses from CDN/proxy cache",
        "severity": "high",
        "typical_payout": "$500-$5K",
    },
    # ── WebSocket chains ──────────────────────────────────
    {
        "id": "WEBSOCKET_HIJACK→DATA",
        "trigger_cwe": "CWE-1385",
        "next_steps": [
            {"action": "cross_site_ws_hijack", "tools": ["websocket-scanner"],
             "escalates_to": "CWE-346"},
            {"action": "exfil_realtime_data", "tools": ["websocket-scanner"],
             "escalates_to": "CWE-200"},
        ],
        "final_impact": "Cross-Site WebSocket Hijacking → real-time data theft",
        "severity": "high",
        "typical_payout": "$500-$5K",
    },
    # ── CRLF Injection chains ─────────────────────────────
    {
        "id": "CRLF→HEADER_INJECT→XSS",
        "trigger_cwe": "CWE-93",
        "next_steps": [
            {"action": "inject_response_headers", "tools": ["crlfuzz"],
             "escalates_to": "CWE-113"},
            {"action": "inject_xss_via_header", "tools": ["crlfuzz"],
             "escalates_to": "CWE-79"},
        ],
        "final_impact": "XSS via CRLF header injection — bypasses CSP in some cases",
        "severity": "high",
        "typical_payout": "$300-$3K",
    },
    # ── Log4j / JNDI chains ──────────────────────────────
    {
        "id": "LOG4J→JNDI→RCE",
        "trigger_cwe": "CWE-917",
        "next_steps": [
            {"action": "confirm_jndi_lookup", "tools": ["log4j-scan"],
             "escalates_to": "CWE-502"},
            {"action": "rce_via_jndi", "tools": ["log4j-scan"],
             "escalates_to": "CWE-78"},
        ],
        "final_impact": "Remote Code Execution via JNDI injection (Log4Shell)",
        "severity": "critical",
        "typical_payout": "$5K-$50K",
    },
    # ── 403 Bypass chains ─────────────────────────────────
    {
        "id": "403_BYPASS→ADMIN_ACCESS",
        "trigger_cwe": "CWE-863",
        "next_steps": [
            {"action": "bypass_acl", "tools": ["bypass-403-advanced"],
             "escalates_to": "CWE-269"},
            {"action": "access_restricted_api", "tools": ["api-discovery"],
             "escalates_to": "CWE-200"},
        ],
        "final_impact": "Access to admin/internal endpoints via 403 bypass",
        "severity": "high",
        "typical_payout": "$500-$5K",
    },
    # ── Brute-force chains ────────────────────────────────
    {
        "id": "USER_ENUM→BRUTE_FORCE→ATO",
        "trigger_cwe": "CWE-307",
        "next_steps": [
            {"action": "enumerate_valid_users", "tools": ["user-enum", "brute-forcer"],
             "escalates_to": "CWE-203"},
            {"action": "brute_force_credentials", "tools": ["brute-forcer", "hydra"],
             "escalates_to": "CWE-521"},
        ],
        "final_impact": "Account Takeover via brute-force after user enumeration",
        "severity": "high",
        "typical_payout": "$500-$5K",
    },
    {
        "id": "DEFAULT_CREDS→ADMIN→DATA",
        "trigger_cwe": "CWE-798",
        "next_steps": [
            {"action": "test_default_credentials", "tools": ["brute-forcer"],
             "escalates_to": "CWE-287"},
            {"action": "access_admin_panel", "tools": ["api-discovery"],
             "escalates_to": "CWE-269"},
        ],
        "final_impact": "Admin access via default credentials → data exfiltration",
        "severity": "critical",
        "typical_payout": "$1K-$10K",
    },
    # ── Command injection chains ──────────────────────────
    {
        "id": "CMDI→RCE→LATERAL",
        "trigger_cwe": "CWE-78",
        "next_steps": [
            {"action": "confirm_os_command_exec", "tools": ["commix"],
             "escalates_to": "CWE-94"},
            {"action": "escalate_to_shell", "tools": ["commix"],
             "escalates_to": "CWE-250"},
        ],
        "final_impact": "Remote Code Execution via OS command injection",
        "severity": "critical",
        "typical_payout": "$5K-$30K",
    },
    # ── OSINT → targeted attack chains ────────────────────
    {
        "id": "EXPOSED_SERVICE→CVE_EXPLOIT",
        "trigger_cwe": "CWE-200",
        "next_steps": [
            {"action": "shodan_service_discovery", "tools": ["osint-enricher", "shodan-cli"],
             "escalates_to": "CWE-1035"},
            {"action": "searchsploit_exploit_lookup", "tools": ["osint-enricher", "searchsploit"],
             "escalates_to": "CWE-94"},
        ],
        "final_impact": "Exploitation of known CVE on exposed service",
        "severity": "high",
        "typical_payout": "$500-$10K",
    },
    # ── Missing security headers + PoC chains ─────────────
    {
        "id": "NO_CSP→XSS→ATO",
        "trigger_cwe": "CWE-79",
        "next_steps": [
            {"action": "verify_csp_missing", "tools": ["header-classifier", "header-poc-generator"],
             "escalates_to": "CWE-79"},
            {"action": "inject_xss_payload", "tools": ["xss-scanner", "dalfox"],
             "escalates_to": "CWE-79"},
            {"action": "exfiltrate_session_tokens", "tools": ["header-poc-generator"],
             "escalates_to": "CWE-522"},
        ],
        "final_impact": "XSS → No CSP → Session hijack / API key theft / ATO on LLM provider",
        "severity": "critical",
        "typical_payout": "$500-$10K",
    },
    {
        "id": "NO_HSTS→MITM→CREDENTIAL_THEFT",
        "trigger_cwe": "CWE-319",
        "next_steps": [
            {"action": "verify_hsts_missing", "tools": ["header-classifier", "header-poc-generator"],
             "escalates_to": "CWE-319"},
            {"action": "sslstrip_mitm_attack", "tools": ["header-poc-generator"],
             "escalates_to": "CWE-300"},
            {"action": "intercept_session_cookies", "tools": [],
             "escalates_to": "CWE-614"},
        ],
        "final_impact": "Protocol downgrade → cleartext credential interception on shared WiFi",
        "severity": "high",
        "typical_payout": "$500-$5K",
    },
    {
        "id": "NO_XFRAME→CLICKJACK→SENSITIVE_ACTION",
        "trigger_cwe": "CWE-1021",
        "next_steps": [
            {"action": "verify_xframe_missing", "tools": ["header-classifier", "header-poc-generator"],
             "escalates_to": "CWE-1021"},
            {"action": "build_clickjacking_poc", "tools": ["header-poc-generator"],
             "escalates_to": "CWE-451"},
            {"action": "trigger_sensitive_action", "tools": [],
             "escalates_to": "CWE-352"},
        ],
        "final_impact": "Clickjacking → unauthorized API key creation / account deletion / settings change",
        "severity": "high",
        "typical_payout": "$300-$3K",
    },
    {
        "id": "NO_CSP→NO_XFRAME→FULL_UI_TAKEOVER",
        "trigger_cwe": "CWE-79",
        "next_steps": [
            {"action": "verify_both_missing", "tools": ["header-poc-generator"],
             "escalates_to": "CWE-1021"},
            {"action": "iframe_xss_combo", "tools": ["xss-scanner", "header-poc-generator"],
             "escalates_to": "CWE-79"},
        ],
        "final_impact": "Combined: iframe the target + inject XSS via missing CSP = full UI takeover",
        "severity": "critical",
        "typical_payout": "$1K-$10K",
    },
]

# Lookup index: CWE → list of applicable chain rules
CHAIN_INDEX: dict[str, list[dict]] = {}
for _rule in CHAIN_RULES:
    _cwe = _rule["trigger_cwe"]
    CHAIN_INDEX.setdefault(_cwe, []).append(_rule)

# Also index by downstream CWEs for reverse lookups
ESCALATION_INDEX: dict[str, list[dict]] = {}
for _rule in CHAIN_RULES:
    for _step in _rule["next_steps"]:
        _esc = _step.get("escalates_to", "")
        if _esc:
            ESCALATION_INDEX.setdefault(_esc, []).append(_rule)
