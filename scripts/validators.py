#!/usr/bin/env python3
"""Validation Gates — structured quality gates for findings before/during/after scan.

7-Question Gate adapted from claude-bug-bounty methodology:
  1. Exploitability — PoC exists? (not theoretical)
  2. Real impact — Affects real user without special action?
  3. Concrete impact — Money, PII, ATO, RCE? (not "theoretically possible")
  4. In-scope — Domain/endpoint within defined scope?
  5. Not duplicate — Not already found or in Hacktivity?
  6. Not rejected — Not a finding that's always rejected?
  7. Triager test — Would a tired triager at 5pm validate this?

Usage:
    from validators import ScanValidator, GateResult
    validator = ScanValidator()
    result = validator.finding_quality_gate(finding)
    # result.verdict in ("PASS", "FAIL", "WARN", "SKIP")

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Literal

# ---------------------------------------------------------------------------
# Core data structures
# ---------------------------------------------------------------------------

@dataclass
class GateResult:
    """Result from a single validation gate."""
    gate_name: str
    verdict: Literal["PASS", "FAIL", "WARN", "SKIP"]
    reason: str
    confidence: float = 1.0  # 0.0–1.0
    suggestion: str | None = None

    def to_dict(self) -> dict:
        d: dict[str, Any] = {
            "gate": self.gate_name,
            "verdict": self.verdict,
            "reason": self.reason,
            "confidence": self.confidence,
        }
        if self.suggestion:
            d["suggestion"] = self.suggestion
        return d


@dataclass
class ValidationSummary:
    """Aggregated validation across all gates for a finding."""
    gates_passed: int = 0
    gates_failed: int = 0
    gates_warned: int = 0
    gates_skipped: int = 0
    total_gates: int = 0
    results: list[GateResult] = field(default_factory=list)
    overall_verdict: Literal["PASS", "WARN", "FAIL", "REJECTED"] = "PASS"
    rejected_reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "gates_passed": self.gates_passed,
            "gates_failed": self.gates_failed,
            "gates_warned": self.gates_warned,
            "gates_skipped": self.gates_skipped,
            "total_gates": self.total_gates,
            "overall_verdict": self.overall_verdict,
            "rejected_reasons": self.rejected_reasons,
            "results": [r.to_dict() for r in self.results],
        }


@dataclass
class ValidationGate:
    """A single quality gate with a check function."""
    name: str
    check: Callable[[dict, dict | None], GateResult]
    phase: Literal["preflight", "finding", "report"] = "finding"


# ---------------------------------------------------------------------------
# Always-rejected findings (noise that platforms never accept)
# ---------------------------------------------------------------------------

ALWAYS_REJECTED: list[dict[str, str | list[str]]] = [
    {
        "id": "missing-csp-header",
        "patterns": ["missing.*content.security.policy", "csp.*not.*set", "no.*csp"],
        "reason": "Missing CSP alone is informational — chain with XSS to report",
        "pass_if": ["poc_html", "chain", "xss"],
    },
    {
        "id": "missing-hsts-header",
        "patterns": ["missing.*hsts", "strict.transport.security.*not", "no.*hsts"],
        "reason": "Missing HSTS alone is informational — chain with MITM PoC",
        "pass_if": ["poc_html", "chain", "sslstrip", "mitm"],
    },
    {
        "id": "missing-x-frame-options",
        "patterns": ["missing.*x.frame", "x.frame.options.*not", "clickjacking.*missing"],
        "reason": "Missing X-Frame-Options alone — chain with clickjacking PoC on sensitive action",
        "pass_if": ["poc_html", "chain", "clickjacking"],
    },
    {
        "id": "graphql-introspection",
        "patterns": ["graphql.*introspection.*enabled", "introspection.*query"],
        "reason": "GraphQL introspection alone is informational — chain with data exposure",
    },
    {
        "id": "server-version-disclosure",
        "patterns": ["server.*version.*disclos", "version.*header.*leak", "server.*banner"],
        "reason": "Version disclosure alone — chain with matching CVE exploit",
    },
    {
        "id": "missing-rate-limiting",
        "patterns": ["missing.*rate.limit", "no.*rate.limit", "rate.limit.*not"],
        "reason": "Missing rate limiting on non-critical endpoints — specify brute-force impact",
    },
    {
        "id": "self-xss",
        "patterns": ["self.xss", "self.*cross.site"],
        "reason": "Self-XSS without chain is not exploitable by attacker",
    },
    {
        "id": "open-redirect-alone",
        "patterns": ["open.*redirect$", "unvalidated.*redirect$"],
        "reason": "Open redirect alone is low — chain with OAuth token theft",
    },
    {
        "id": "cors-wildcard",
        "patterns": ["cors.*wildcard", "access.control.*\\*"],
        "reason": "CORS wildcard without credential exfiltration PoC",
    },
    {
        "id": "missing-spf-dmarc",
        "patterns": ["missing.*spf", "missing.*dmarc", "spf.*not.*set", "dmarc.*not.*set"],
        "reason": "Missing SPF/DMARC is purely informational",
    },
    {
        "id": "directory-listing",
        "patterns": ["directory.*listing", "index.*of.*parent"],
        "reason": "Directory listing alone — chain with sensitive file access",
    },
    {
        "id": "cookie-flags",
        "patterns": ["cookie.*httponly", "cookie.*secure.*flag", "missing.*cookie.*flag"],
        "reason": "Missing cookie flags alone — chain with XSS session hijacking",
    },
    {
        "id": "robots-txt-info",
        "patterns": ["robots\\.txt.*disclos", "sensitive.*path.*robots"],
        "reason": "robots.txt information disclosure alone",
    },
]

# Compile reject patterns once
_REJECT_COMPILED: list[tuple[str, list[re.Pattern[str]], str, list[str]]] = []
for _rule in ALWAYS_REJECTED:
    _patterns = [re.compile(p, re.IGNORECASE) for p in _rule["patterns"]]  # type: ignore[union-attr]
    _pass_if = _rule.get("pass_if", [])  # type: ignore[union-attr]
    _REJECT_COMPILED.append((_rule["id"], _patterns, _rule["reason"], _pass_if))  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# CWEs with high exploitability indicators
# ---------------------------------------------------------------------------

HIGH_IMPACT_CWES = {
    "CWE-89",   # SQLi
    "CWE-78",   # OS command injection
    "CWE-79",   # XSS (with PoC)
    "CWE-918",  # SSRF
    "CWE-502",  # Deserialization
    "CWE-94",   # Code injection
    "CWE-22",   # Path traversal
    "CWE-287",  # Authentication bypass
    "CWE-862",  # Missing authz
    "CWE-863",  # Incorrect authz
    "CWE-639",  # IDOR
    "CWE-434",  # Unrestricted upload
    "CWE-611",  # XXE
    "CWE-1321", # Prototype pollution
}

THEORETICAL_KEYWORDS = [
    "theoretical", "theoretically", "might be", "could potentially",
    "may allow", "not verified", "not confirmed", "unconfirmed",
    "possible", "potentially vulnerable",
]

POC_INDICATORS = [
    "poc_url", "poc_request", "curl_command", "poc", "proof",
    "http_request", "exploit_url", "payload_used", "matched",
    "evidence", "curl", "request_response",
]


# ---------------------------------------------------------------------------
# Gate implementations
# ---------------------------------------------------------------------------

def _gate_exploitability(finding: dict, _ctx: dict | None = None) -> GateResult:
    """Gate 1: Is there a PoC / concrete evidence, not just theoretical?"""
    # Check for PoC indicators
    has_poc = False
    for key in POC_INDICATORS:
        val = finding.get(key)
        if val and str(val).strip():
            has_poc = True
            break

    # Check evidence object
    evidence = finding.get("evidence", {})
    if isinstance(evidence, dict) and evidence:
        has_poc = True
    elif isinstance(evidence, str) and len(evidence) > 20:
        has_poc = True

    # Check if description is purely theoretical
    desc = (finding.get("description", "") + " " + finding.get("title", "")).lower()
    is_theoretical = any(kw in desc for kw in THEORETICAL_KEYWORDS)

    if has_poc and not is_theoretical:
        return GateResult("exploitability", "PASS", "PoC or evidence present")
    if has_poc and is_theoretical:
        return GateResult("exploitability", "WARN", "Evidence present but language is theoretical",
                          confidence=0.6, suggestion="Strengthen PoC with concrete HTTP request")
    if not has_poc and not is_theoretical:
        return GateResult("exploitability", "WARN", "No PoC found — add curl/HTTP evidence",
                          confidence=0.4, suggestion="Add PoC URL or HTTP request/response")
    return GateResult("exploitability", "FAIL", "Theoretical finding without PoC",
                      confidence=0.8, suggestion="Reproduce and add concrete PoC before reporting")


def _gate_real_impact(finding: dict, _ctx: dict | None = None) -> GateResult:
    """Gate 2: Does this affect a real user without special/unlikely action?"""
    sev = (finding.get("severity") or "info").lower()
    cwe_raw = finding.get("cwe") or finding.get("cwe_id") or finding.get("cwe_normalized") or ""
    if isinstance(cwe_raw, list):
        cwe_raw = cwe_raw[0] if cwe_raw else ""
    cwe = str(cwe_raw).upper()

    if sev in ("critical", "high") and cwe in HIGH_IMPACT_CWES:
        return GateResult("real_impact", "PASS", f"High severity {cwe} — real user impact")
    if sev == "critical":
        return GateResult("real_impact", "PASS", "Critical severity implies real user impact")
    if sev == "high":
        return GateResult("real_impact", "PASS", "High severity — likely real impact",
                          confidence=0.8)
    if sev == "medium":
        if cwe in HIGH_IMPACT_CWES:
            return GateResult("real_impact", "PASS", f"{cwe} with medium severity — real impact")
        return GateResult("real_impact", "WARN",
                          "Medium severity — ensure impact on real user without special conditions",
                          confidence=0.6,
                          suggestion="Clarify the user impact scenario in the report")
    return GateResult("real_impact", "WARN",
                      f"Low/info severity ({sev}) — limited user impact",
                      confidence=0.3,
                      suggestion="Consider if this can be chained for higher impact")


def _gate_concrete_impact(finding: dict, _ctx: dict | None = None) -> GateResult:
    """Gate 3: Is there concrete impact (money, PII, ATO, RCE)?"""
    title = (finding.get("title") or finding.get("name") or "").lower()
    desc = (finding.get("description") or "").lower()
    text = f"{title} {desc}"
    cwe = get_cwe(finding)

    # Concrete impact keywords
    concrete = [
        "rce", "remote code execution", "account takeover", "ato",
        "data exfiltration", "pii", "personal data", "credential",
        "password", "session hijack", "admin access", "privilege escalation",
        "payment", "financial", "money", "gdpr", "sql injection",
        "command injection", "file write", "arbitrary file",
    ]
    found_impacts = [kw for kw in concrete if kw in text]

    if found_impacts or cwe in HIGH_IMPACT_CWES:
        return GateResult("concrete_impact", "PASS",
                          f"Concrete impact: {', '.join(found_impacts[:3]) or cwe}")
    sev = (finding.get("severity") or "info").lower()
    if sev in ("critical", "high"):
        return GateResult("concrete_impact", "WARN",
                          "High severity but concrete impact not explicit in description",
                          confidence=0.5,
                          suggestion="Explicitly state: what data/action is compromised")
    return GateResult("concrete_impact", "FAIL",
                      "No concrete impact demonstrated (money, PII, ATO, RCE)",
                      confidence=0.7,
                      suggestion="Add impact statement: what can attacker steal/do?")


def _gate_in_scope(finding: dict, ctx: dict | None = None) -> GateResult:
    """Gate 4: Is the finding target within the defined scope?"""
    if not ctx or "scope_enforcer" not in ctx:
        return GateResult("in_scope", "SKIP", "No scope defined — skipping scope check")

    scope_enforcer = ctx["scope_enforcer"]
    url = finding.get("url") or finding.get("endpoint") or ""
    if not url:
        return GateResult("in_scope", "WARN", "No URL in finding — cannot verify scope",
                          confidence=0.5,
                          suggestion="Add target URL to finding")

    try:
        if scope_enforcer.is_in_scope(url):
            return GateResult("in_scope", "PASS", f"URL {url[:60]} is in scope")
        return GateResult("in_scope", "FAIL", f"URL {url[:60]} is OUT OF SCOPE",
                          suggestion="Remove or re-scope this finding")
    except Exception:
        return GateResult("in_scope", "SKIP", "Scope check error",
                          confidence=0.0)


def _gate_not_duplicate(finding: dict, ctx: dict | None = None) -> GateResult:
    """Gate 5: Is this finding a duplicate of something already reported?"""
    # Check internal dedup
    dup = finding.get("duplicate_of")
    if dup:
        return GateResult("not_duplicate", "FAIL",
                          f"Duplicate of {dup}",
                          suggestion="Remove or merge with original finding")
    dup_count = finding.get("duplicate_count", 0)
    if dup_count and int(dup_count) > 0:
        return GateResult("not_duplicate", "WARN",
                          f"Has {dup_count} similar findings — verify not duplicate",
                          confidence=0.6)

    # Check memory for past findings on same endpoint
    if ctx and "memory" in ctx:
        memory = ctx["memory"]
        try:
            url = finding.get("url", "")
            cwe = finding.get("cwe", "")
            if url and cwe and memory.available:
                past = memory.recall_similar({"url": url, "cwe": cwe}, limit=3)
                if past:
                    return GateResult("not_duplicate", "WARN",
                                      f"Memory has {len(past)} similar past findings",
                                      confidence=0.5,
                                      suggestion="Check Hacktivity for duplicates")
        except Exception:
            pass

    return GateResult("not_duplicate", "PASS", "No duplicate detected")


def _gate_not_rejected(finding: dict, _ctx: dict | None = None) -> GateResult:
    """Gate 6: Is this finding in the always-rejected list?"""
    title = (finding.get("title") or finding.get("name") or "").lower()
    desc = (finding.get("description") or "").lower()
    text = f"{title} {desc}"
    evidence = finding.get("evidence", {})
    evidence_str = json.dumps(evidence).lower() if isinstance(evidence, dict) else str(evidence).lower()

    for rule_id, patterns, reason, pass_if in _REJECT_COMPILED:
        for pat in patterns:
            if pat.search(text):
                # Check if it's chained (chains make rejected findings valid)
                chains = finding.get("chains", [])
                if chains:
                    return GateResult("not_rejected", "PASS",
                                      f"Matched reject pattern '{rule_id}' but has chain — valid",
                                      confidence=0.8)
                # Check if evidence contains PoC artifacts (pass_if keywords)
                if pass_if:
                    full_text = f"{text} {evidence_str}"
                    if any(kw in full_text for kw in pass_if):
                        return GateResult("not_rejected", "PASS",
                                          f"Matched reject pattern '{rule_id}' but PoC evidence present — valid",
                                          confidence=0.85)
                return GateResult("not_rejected", "FAIL", reason,
                                  suggestion=f"Chain with another vuln or remove ({rule_id})")
    return GateResult("not_rejected", "PASS", "Not in rejected list")


def _gate_triager_test(finding: dict, _ctx: dict | None = None) -> GateResult:
    """Gate 7: Would a tired triager at 5pm validate this? Heuristic quality check."""
    score = 0
    issues: list[str] = []

    # Has title?
    title = finding.get("title") or finding.get("name") or ""
    if len(title) > 10:
        score += 1
    else:
        issues.append("missing/short title")

    # Has description?
    desc = finding.get("description") or ""
    if len(desc) > 50:
        score += 1
    else:
        issues.append("missing/short description")

    # Has URL?
    url = finding.get("url") or finding.get("endpoint") or ""
    if url:
        score += 1
    else:
        issues.append("no target URL")

    # Has severity?
    sev = finding.get("severity", "")
    if sev and sev.lower() in ("critical", "high", "medium", "low", "info"):
        score += 1
    else:
        issues.append("missing severity")

    # Has CWE?
    cwe = get_cwe(finding)
    if cwe:
        score += 1
    else:
        issues.append("no CWE reference")

    # Has evidence/PoC?
    has_evidence = any(finding.get(k) for k in POC_INDICATORS)
    if has_evidence:
        score += 1
    else:
        issues.append("no evidence/PoC")

    # Has remediation?
    if finding.get("remediation"):
        score += 1
    else:
        issues.append("no remediation")

    # Score out of 7
    if score >= 6:
        return GateResult("triager_test", "PASS",
                          f"Report quality {score}/7 — triager would accept",
                          confidence=score / 7)
    if score >= 4:
        return GateResult("triager_test", "WARN",
                          f"Report quality {score}/7 — needs improvement: {', '.join(issues)}",
                          confidence=score / 7,
                          suggestion=f"Add: {', '.join(issues)}")
    return GateResult("triager_test", "FAIL",
                      f"Report quality {score}/7 — triager would reject: {', '.join(issues)}",
                      confidence=score / 7,
                      suggestion=f"Add: {', '.join(issues)}")


# ---------------------------------------------------------------------------
# Preflight gates (run before scan)
# ---------------------------------------------------------------------------

def _gate_scope_valid(finding: dict, ctx: dict | None = None) -> GateResult:
    """Preflight: Is the scope definition valid?"""
    if not ctx or "scope" not in ctx:
        return GateResult("scope_valid", "FAIL", "No scope provided")
    scope = ctx["scope"]
    targets = scope.get("targets", [])
    if not targets:
        return GateResult("scope_valid", "FAIL", "Scope has no targets defined")
    return GateResult("scope_valid", "PASS", f"Scope has {len(targets)} target(s)")


def _gate_target_accessible(finding: dict, ctx: dict | None = None) -> GateResult:
    """Preflight: Is the target actually accessible?"""
    if not ctx or "target_status" not in ctx:
        return GateResult("target_accessible", "SKIP", "No target status available")
    status = ctx["target_status"]
    if status.get("up"):
        code = status.get("status_code", 0)
        return GateResult("target_accessible", "PASS",
                          f"Target is up (HTTP {code})")
    return GateResult("target_accessible", "FAIL",
                      f"Target appears down: {status.get('error', 'unknown')}",
                      suggestion="Verify target URL and check if behind WAF/VPN")


def _gate_auth_ready(finding: dict, ctx: dict | None = None) -> GateResult:
    """Preflight: Are auth tokens/cookies available if needed?"""
    if not ctx:
        return GateResult("auth_ready", "SKIP", "No context available")
    needs_auth = ctx.get("needs_auth", False)
    has_auth = ctx.get("has_auth", False)
    if not needs_auth:
        return GateResult("auth_ready", "PASS", "No authentication required")
    if has_auth:
        return GateResult("auth_ready", "PASS", "Auth tokens configured")
    return GateResult("auth_ready", "FAIL",
                      "Scope requires auth but no tokens configured",
                      suggestion="Set auth tokens in scope config or environment")


# ---------------------------------------------------------------------------
# ScanValidator — orchestrates all gates
# ---------------------------------------------------------------------------

class ScanValidator:
    """Orchestrates validation gates before, during, and after scan."""

    FINDING_GATES = [
        ValidationGate("exploitability", _gate_exploitability, "finding"),
        ValidationGate("real_impact", _gate_real_impact, "finding"),
        ValidationGate("concrete_impact", _gate_concrete_impact, "finding"),
        ValidationGate("in_scope", _gate_in_scope, "finding"),
        ValidationGate("not_duplicate", _gate_not_duplicate, "finding"),
        ValidationGate("not_rejected", _gate_not_rejected, "finding"),
        ValidationGate("triager_test", _gate_triager_test, "finding"),
    ]

    PREFLIGHT_GATES = [
        ValidationGate("scope_valid", _gate_scope_valid, "preflight"),
        ValidationGate("target_accessible", _gate_target_accessible, "preflight"),
        ValidationGate("auth_ready", _gate_auth_ready, "preflight"),
    ]

    def __init__(self, scope_enforcer: Any = None, memory: Any = None):
        self._ctx: dict[str, Any] = {}
        if scope_enforcer:
            self._ctx["scope_enforcer"] = scope_enforcer
        if memory:
            self._ctx["memory"] = memory

    def preflight_check(self, ctx: dict | None = None) -> list[GateResult]:
        """Run preflight gates before scan starts."""
        merged = {**self._ctx, **(ctx or {})}
        results = []
        for gate in self.PREFLIGHT_GATES:
            result = gate.check({}, merged)
            results.append(result)
        return results

    def finding_quality_gate(self, finding: dict, ctx: dict | None = None) -> ValidationSummary:
        """Run all 7 quality gates on a single finding."""
        merged = {**self._ctx, **(ctx or {})}
        summary = ValidationSummary()
        summary.total_gates = len(self.FINDING_GATES)

        for gate in self.FINDING_GATES:
            result = gate.check(finding, merged)
            summary.results.append(result)
            if result.verdict == "PASS":
                summary.gates_passed += 1
            elif result.verdict == "FAIL":
                summary.gates_failed += 1
                summary.rejected_reasons.append(f"{result.gate_name}: {result.reason}")
            elif result.verdict == "WARN":
                summary.gates_warned += 1
            else:  # SKIP
                summary.gates_skipped += 1

        # Determine overall verdict
        if summary.gates_failed > 0:
            # Check if it's a hard reject (rejected list or out of scope)
            hard_fails = [r for r in summary.results
                          if r.verdict == "FAIL"
                          and r.gate_name in ("not_rejected", "in_scope")]
            if hard_fails:
                summary.overall_verdict = "REJECTED"
            else:
                summary.overall_verdict = "FAIL"
        elif summary.gates_warned > 2:
            summary.overall_verdict = "WARN"
        elif summary.gates_warned > 0:
            summary.overall_verdict = "WARN"
        else:
            summary.overall_verdict = "PASS"

        return summary

    def validate_report(self, findings: list[dict],
                        ctx: dict | None = None) -> dict[str, Any]:
        """Run all quality gates on a list of findings. Returns validated + rejected."""
        validated: list[dict] = []
        rejected: list[dict] = []
        warned: list[dict] = []

        for finding in findings:
            summary = self.finding_quality_gate(finding, ctx)
            finding_copy = dict(finding)
            finding_copy["validation"] = summary.to_dict()

            if summary.overall_verdict == "REJECTED":
                rejected.append(finding_copy)
            elif summary.overall_verdict == "FAIL":
                rejected.append(finding_copy)
            elif summary.overall_verdict == "WARN":
                warned.append(finding_copy)
                validated.append(finding_copy)
            else:
                validated.append(finding_copy)

        return {
            "validated": validated,
            "rejected": rejected,
            "warned": warned,
            "stats": {
                "total": len(findings),
                "validated": len(validated),
                "rejected": len(rejected),
                "warned": len(warned),
                "pass_rate": len(validated) / max(len(findings), 1),
            },
        }


# ---------------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------------

def validate_finding(finding: dict, **kwargs: Any) -> ValidationSummary:
    """Quick validate a single finding."""
    validator = ScanValidator(**kwargs)
    return validator.finding_quality_gate(finding)


def is_always_rejected(title: str, description: str = "", evidence: dict | None = None) -> str | None:
    """Check if a finding matches the always-rejected list. Returns reason or None.

    Findings with PoC evidence (poc_html, chain keywords) bypass rejection.
    """
    text = f"{title} {description}".lower()
    evidence_str = json.dumps(evidence).lower() if isinstance(evidence, dict) else ""
    for rule_id, patterns, reason, pass_if in _REJECT_COMPILED:
        for pat in patterns:
            if pat.search(text):
                # If pass_if keywords found in evidence, don't reject
                if pass_if:
                    full_text = f"{text} {evidence_str}"
                    if any(kw in full_text for kw in pass_if):
                        return None
                return reason
    return None

def get_cwe(finding):
    cwe = finding.get("cwe") or finding.get("cwe_id") or finding.get("cwe_normalized") or ""
    if isinstance(cwe, list):
        cwe = cwe[0] if cwe else ""
    return str(cwe).upper()
