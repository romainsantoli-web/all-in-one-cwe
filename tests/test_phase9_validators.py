#!/usr/bin/env python3
"""Tests for Phase 9 — Validation Gates.
⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

passed = 0
failed = 0
errors: list[str] = []


def test(name: str, condition: bool, detail: str = ""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  ✓ {name}")
    else:
        failed += 1
        errors.append(f"{name}: {detail}")
        print(f"  ✗ {name} — {detail}")


# ── Import tests ──────────────────────────────────────

print("\n─── Import Tests ───")
try:
    from validators import (
        ScanValidator,
        GateResult,
        ValidationSummary,
        ValidationGate,
        ALWAYS_REJECTED,
        validate_finding,
        is_always_rejected,
    )
    test("T1: validators module imports", True)
except ImportError as e:
    test("T1: validators module imports", False, str(e))
    # Can't continue without imports
    print(f"\nPhase 9 Tests: {passed} passed, {failed} failed")
    sys.exit(1)


# ── GateResult tests ─────────────────────────────────

print("\n─── GateResult Tests ───")
gr = GateResult("test_gate", "PASS", "looks good", confidence=0.9)
test("T2: GateResult to_dict keys", set(gr.to_dict().keys()) >= {"gate", "verdict", "reason", "confidence"})
test("T3: GateResult verdict is PASS", gr.verdict == "PASS")
gr_suggestion = GateResult("test", "WARN", "maybe", suggestion="fix it")
test("T4: GateResult with suggestion", "suggestion" in gr_suggestion.to_dict())


# ── ALWAYS_REJECTED tests ────────────────────────────

print("\n─── Always-Rejected List Tests ───")
test("T5: ALWAYS_REJECTED has ≥10 entries", len(ALWAYS_REJECTED) >= 10)
test("T6: Each entry has id/patterns/reason",
     all("id" in r and "patterns" in r and "reason" in r for r in ALWAYS_REJECTED))


# ── is_always_rejected tests ─────────────────────────

print("\n─── is_always_rejected Tests ───")
test("T7: Missing CSP rejected",
     is_always_rejected("Missing Content-Security-Policy Header") is not None)
test("T8: SSRF not rejected",
     is_always_rejected("Server-Side Request Forgery") is None)
test("T9: Self-XSS rejected",
     is_always_rejected("Self-XSS in profile page") is not None)
test("T10: Missing HSTS rejected",
     is_always_rejected("Missing HSTS header") is not None)
test("T11: SQL Injection not rejected",
     is_always_rejected("SQL Injection in login") is None)
test("T12: GraphQL introspection rejected",
     is_always_rejected("GraphQL Introspection Enabled") is not None)
test("T13: CORS wildcard rejected",
     is_always_rejected("CORS Wildcard on API endpoint") is not None)


# ── Single finding validation tests ──────────────────

print("\n─── Finding Validation Tests ───")

# High quality SSRF finding — should PASS
ssrf_finding = {
    "title": "Server-Side Request Forgery (SSRF)",
    "name": "SSRF",
    "severity": "critical",
    "cwe": "CWE-918",
    "url": "https://target.com/api/fetch",
    "description": "Full SSRF allowing remote code execution via cloud metadata access",
    "evidence": {"request": "GET /api/fetch?url=http://169.254.169.254/latest/meta-data/"},
    "remediation": "Validate and whitelist URLs in the fetch parameter",
    "poc_url": "https://target.com/api/fetch?url=http://169.254.169.254/",
}
summary = validate_finding(ssrf_finding)
test("T14: SSRF passes all gates", summary.overall_verdict == "PASS",
     f"got {summary.overall_verdict}, failed={summary.gates_failed}")
test("T15: SSRF has 7 total gates", summary.total_gates == 7)

# Missing CSP — should be REJECTED
csp_finding = {
    "title": "Missing Content-Security-Policy Header",
    "severity": "info",
    "cwe": "",
    "url": "https://target.com",
    "tool": "nuclei",
    "description": "The CSP header is not set on the response",
}
summary_csp = validate_finding(csp_finding)
test("T16: Missing CSP is REJECTED", summary_csp.overall_verdict == "REJECTED",
     f"got {summary_csp.overall_verdict}")
test("T17: CSP has rejected reasons", len(summary_csp.rejected_reasons) > 0)

# Theoretical finding — should FAIL or WARN
theoretical = {
    "title": "Possible XSS",
    "severity": "medium",
    "cwe": "CWE-79",
    "url": "https://target.com/search",
    "description": "This endpoint might be vulnerable to XSS. Not verified.",
    "tool": "scanner",
}
summary_theo = validate_finding(theoretical)
test("T18: Theoretical finding not PASS", summary_theo.overall_verdict != "PASS",
     f"got {summary_theo.overall_verdict}")

# Minimal finding — triager should reject
minimal = {
    "title": "Bug",
    "severity": "",
    "tool": "test",
}
summary_min = validate_finding(minimal)
test("T19: Minimal finding fails triager test",
     any(r.gate_name == "triager_test" and r.verdict == "FAIL" for r in summary_min.results))


# ── ScanValidator tests ──────────────────────────────

print("\n─── ScanValidator Tests ───")

validator = ScanValidator()

# Preflight
preflight = validator.preflight_check({"scope": {"targets": ["https://example.com"]}})
test("T20: Preflight returns 3 results", len(preflight) == 3)
test("T21: Scope valid passes",
     any(r.gate_name == "scope_valid" and r.verdict == "PASS" for r in preflight))

# Preflight without scope
preflight_empty = validator.preflight_check({})
test("T22: Preflight without scope fails scope_valid",
     any(r.gate_name == "scope_valid" and r.verdict == "FAIL" for r in preflight_empty))

# validate_report
findings_batch = [
    ssrf_finding,
    csp_finding,
    {
        "title": "SQL Injection in search",
        "severity": "critical",
        "cwe": "CWE-89",
        "url": "https://target.com/search?q=test",
        "description": "SQL injection allows data exfiltration of the entire database",
        "evidence": {"request": "GET /search?q=1' OR 1=1--"},
        "remediation": "Use parameterized queries",
        "tool": "sqlmap",
    },
]
result = validator.validate_report(findings_batch)
test("T23: validate_report has validated key", "validated" in result)
test("T24: validate_report has rejected key", "rejected" in result)
test("T25: CSP in rejected", len(result["rejected"]) >= 1)
test("T26: SSRF in validated", len(result["validated"]) >= 1)
test("T27: Stats has pass_rate", "pass_rate" in result["stats"])
test("T28: Stats total count correct", result["stats"]["total"] == 3)

# Each validated finding has validation metadata
for f in result["validated"]:
    has_val = "validation" in f
    if not has_val:
        test("T29: Validated findings have validation metadata", False, f"missing on {f.get('title')}")
        break
else:
    test("T29: Validated findings have validation metadata", True)


# ── ValidationSummary tests ──────────────────────────

print("\n─── ValidationSummary Tests ───")
vs = ValidationSummary()
vs.gates_passed = 5
vs.gates_failed = 1
vs.gates_warned = 1
vs.total_gates = 7
vs.results = [GateResult("test", "PASS", "ok")]
vs.rejected_reasons = ["test: reason"]
d = vs.to_dict()
test("T30: ValidationSummary.to_dict has all keys",
     set(d.keys()) >= {"gates_passed", "gates_failed", "total_gates", "overall_verdict", "results"})


# ── Gate-specific tests ──────────────────────────────

print("\n─── Gate-Specific Tests ───")

# Exploitability with PoC
from validators import _gate_exploitability, _gate_not_rejected, _gate_triager_test

poc_finding = {"title": "SSRF", "poc_url": "http://...", "description": "SSRF found"}
test("T31: Exploitability PASS with PoC", _gate_exploitability(poc_finding).verdict == "PASS")

no_poc = {"title": "SSRF", "description": "Possible SSRF, not verified"}
test("T32: Exploitability FAIL without PoC + theoretical",
     _gate_exploitability(no_poc).verdict == "FAIL")

# Not-rejected with chains (should pass even if pattern matches)
chained_csp = {
    "title": "Missing CSP Header",
    "description": "CSP not set",
    "chains": [{"id": "xss-csp"}],
}
test("T33: Chained rejected finding passes",
     _gate_not_rejected(chained_csp).verdict == "PASS")

# Triager test scoring
good_finding = {
    "title": "SQL Injection in login form allows full DB access",
    "description": "The login endpoint is vulnerable to SQL injection via the username parameter. An attacker can extract all user credentials.",
    "url": "https://target.com/login",
    "severity": "critical",
    "cwe": "CWE-89",
    "evidence": {"request": "POST /login username=admin'--"},
    "remediation": "Use parameterized SQL queries",
}
test("T34: Good finding passes triager test",
     _gate_triager_test(good_finding).verdict == "PASS")


# ── Integration checks ───────────────────────────────

print("\n─── Integration Checks ───")

# smart_scan.py imports validators
import importlib
smart_spec = importlib.util.find_spec("smart_scan", [str(Path(__file__).parent.parent / "scripts")])
if smart_spec and smart_spec.origin:
    source = Path(smart_spec.origin).read_text()
    test("T35: smart_scan imports ScanValidator",
         "from validators import ScanValidator" in source)
    test("T36: smart_scan has preflight_check",
         "preflight_check" in source)
    test("T37: smart_scan has validation_gates step",
         "validation_gates" in source or "validate_report" in source)
    test("T38: smart_scan exports rejected findings",
         "rejected-findings.json" in source)
else:
    test("T35: smart_scan imports ScanValidator", False, "module not found")
    test("T36: smart_scan has preflight_check", False, "module not found")
    test("T37: smart_scan has validation_gates step", False, "module not found")
    test("T38: smart_scan exports rejected findings", False, "module not found")

# merge-reports.py imports validators
merge_path = Path(__file__).parent.parent / "scripts" / "merge-reports.py"
if merge_path.exists():
    merge_src = merge_path.read_text()
    test("T39: merge-reports imports ScanValidator",
         "from validators import ScanValidator" in merge_src)
    test("T40: merge-reports calls finding_quality_gate",
         "finding_quality_gate" in merge_src)
else:
    test("T39: merge-reports imports ScanValidator", False, "file not found")
    test("T40: merge-reports calls finding_quality_gate", False, "file not found")


# ── Duplicate gate with memory mock ──────────────────

print("\n─── Duplicate Gate Tests ───")

from validators import _gate_not_duplicate

# Finding marked as duplicate
dup_finding = {"title": "XSS", "duplicate_of": "finding-123"}
test("T41: Duplicate finding detected",
     _gate_not_duplicate(dup_finding).verdict == "FAIL")

# Finding not duplicate
clean_finding = {"title": "XSS", "url": "https://example.com"}
test("T42: Non-duplicate passes",
     _gate_not_duplicate(clean_finding).verdict == "PASS")


# ── Summary ──────────────────────────────────────────

print(f"\n{'='*50}")
print(f"Phase 9 Tests: {passed} passed, {failed} failed")
if errors:
    print("Failures:")
    for e in errors:
        print(f"  ✗ {e}")
print(f"{'='*50}")

sys.exit(1 if failed else 0)
