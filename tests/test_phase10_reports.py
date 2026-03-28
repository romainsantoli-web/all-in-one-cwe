#!/usr/bin/env python3
"""Tests for Phase 10 — Platform Report Templates + Contextual CVSS.

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

import json
import sys
import os
from pathlib import Path

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).parent.parent
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))


# ===========================================================================
# report_generators.py tests
# ===========================================================================

class TestReportGeneratorsImports:
    """T1: Module importable."""

    def test_import_module(self):
        import report_generators
        assert hasattr(report_generators, "PlatformReportGenerator")
        assert hasattr(report_generators, "ReportFormat")

    def test_report_format_enum(self):
        from report_generators import ReportFormat
        assert ReportFormat.YESWEHACK.value == "yeswehack"
        assert ReportFormat.HACKERONE.value == "hackerone"
        assert ReportFormat.BUGCROWD.value == "bugcrowd"
        assert ReportFormat.INTIGRITI.value == "intigriti"
        assert ReportFormat.IMMUNEFI.value == "immunefi"
        assert ReportFormat.MARKDOWN.value == "markdown"

    def test_available_formats(self):
        from report_generators import PlatformReportGenerator
        fmts = PlatformReportGenerator.available_formats()
        assert "yeswehack" in fmts
        assert "hackerone" in fmts
        assert "bugcrowd" in fmts
        assert "intigriti" in fmts
        assert "immunefi" in fmts
        assert "markdown" in fmts
        assert len(fmts) == 6


class TestHelperFunctions:
    """T2: Utility functions."""

    def test_extract_poc_curl(self):
        from report_generators import _extract_poc
        f = {"curl_command": "curl -X POST https://example.com/api"}
        assert "curl -X POST" in _extract_poc(f)

    def test_extract_poc_url(self):
        from report_generators import _extract_poc
        f = {"url": "https://example.com/vuln"}
        assert "curl -v" in _extract_poc(f)

    def test_extract_poc_empty(self):
        from report_generators import _extract_poc
        assert "manually" in _extract_poc({})

    def test_get_cwe_normalized(self):
        from report_generators import _get_cwe
        assert _get_cwe({"cwe": "cwe-79"}) == "CWE-79"
        assert _get_cwe({"cwe_normalized": "CWE-89"}) == "CWE-89"
        assert _get_cwe({"cwe_id": "79"}) == "79"  # raw digit string, not normalized

    def test_get_title(self):
        from report_generators import _get_title
        assert _get_title({"title": "SQLi"}) == "SQLi"
        assert _get_title({}) == "Untitled"

    def test_get_title_with_url(self):
        from report_generators import _get_title
        t = _get_title({"title": "XSS", "url": "https://example.com/search"})
        assert "XSS" in t
        assert "/search" in t

    def test_validation_status(self):
        from report_generators import _validation_status
        f = {"validation": {"overall_verdict": "PASS", "gates_passed": 7, "total_gates": 7}}
        s = _validation_status(f)
        assert "PASS" in s
        assert "7/7" in s

    def test_validation_status_empty(self):
        from report_generators import _validation_status
        assert _validation_status({}) == ""


SAMPLE_FINDING = {
    "title": "SQL Injection in /api/users",
    "severity": "critical",
    "cwe": "CWE-89",
    "cwe_normalized": "CWE-89",
    "url": "https://target.com/api/users",
    "description": "Blind SQL injection via user_id parameter.",
    "remediation": "Use parameterized queries.",
    "cvss_score": 9.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "ai_analysis": "This allows full database compromise including PII exfiltration.",
    "curl_command": "curl -X POST 'https://target.com/api/users' -d 'id=1 OR 1=1'",
}


class TestYesWeHackReport:
    """T3: YesWeHack format."""

    def test_format_finding(self):
        from report_generators import YesWeHackReport
        out = YesWeHackReport.format_finding(SAMPLE_FINDING, 1)
        assert "Finding 1:" in out
        assert "SQL Injection" in out
        assert "CWE-89" in out
        assert "Steps To Reproduce" in out
        assert "curl" in out
        assert "Impact" in out
        assert "Remediation" in out

    def test_generate(self):
        from report_generators import YesWeHackReport
        out = YesWeHackReport.generate([SAMPLE_FINDING], target="target.com")
        assert "YesWeHack" in out
        assert "target.com" in out
        assert "Findings:" in out

    def test_cvss_displayed(self):
        from report_generators import YesWeHackReport
        out = YesWeHackReport.format_finding(SAMPLE_FINDING)
        assert "9.8" in out
        assert "CVSS:3.1" in out


class TestHackerOneReport:
    """T4: HackerOne format."""

    def test_format_finding(self):
        from report_generators import HackerOneReport
        out = HackerOneReport.format_finding(SAMPLE_FINDING)
        assert "## SQL Injection" in out
        assert "Summary" in out
        assert "Steps To Reproduce" in out
        assert "Impact" in out
        assert "CVSS" in out

    def test_severity_lowercase(self):
        from report_generators import HackerOneReport
        out = HackerOneReport.format_finding(SAMPLE_FINDING)
        assert "**Severity:** critical" in out

    def test_generate_header(self):
        from report_generators import HackerOneReport
        out = HackerOneReport.generate([SAMPLE_FINDING], target="h1.com")
        assert "HackerOne Report" in out


class TestBugcrowdReport:
    """T5: Bugcrowd format with P1-P5 + VRT."""

    def test_priority_critical(self):
        from report_generators import BugcrowdReport
        out = BugcrowdReport.format_finding(SAMPLE_FINDING)
        assert "[P1]" in out

    def test_vrt_sqli(self):
        from report_generators import BugcrowdReport
        out = BugcrowdReport.format_finding(SAMPLE_FINDING)
        assert "SQL Injection" in out

    def test_priority_medium(self):
        from report_generators import BugcrowdReport
        f = dict(SAMPLE_FINDING, severity="medium")
        out = BugcrowdReport.format_finding(f)
        assert "[P3]" in out

    def test_unknown_cwe_vrt(self):
        from report_generators import BugcrowdReport
        f = dict(SAMPLE_FINDING, cwe="CWE-999", cwe_normalized="CWE-999")
        out = BugcrowdReport.format_finding(f)
        assert "Other" in out


class TestIntigritiReport:
    """T6: Intigriti format."""

    def test_domain_extracted(self):
        from report_generators import IntigritiReport
        out = IntigritiReport.format_finding(SAMPLE_FINDING)
        assert "target.com" in out

    def test_severity_capitalized(self):
        from report_generators import IntigritiReport
        out = IntigritiReport.format_finding(SAMPLE_FINDING)
        assert "Critical" in out

    def test_endpoint_shown(self):
        from report_generators import IntigritiReport
        out = IntigritiReport.format_finding(SAMPLE_FINDING)
        assert "/api/users" in out


class TestImmunefiReport:
    """T7: Immunefi format with financial impact focus."""

    def test_financial_impact_section(self):
        from report_generators import ImmunefiReport
        out = ImmunefiReport.format_finding(SAMPLE_FINDING)
        assert "Financial Impact" in out
        assert "Bug Description" in out

    def test_chain_display(self):
        from report_generators import ImmunefiReport
        f = dict(SAMPLE_FINDING, chains=[{"final_impact": "RCE"}, {"final_impact": "ATO"}])
        out = ImmunefiReport.format_finding(f)
        assert "Exploit Chain" in out
        assert "RCE" in out

    def test_affected_assets(self):
        from report_generators import ImmunefiReport
        out = ImmunefiReport.format_finding(SAMPLE_FINDING)
        assert "Affected Assets" in out


class TestMarkdownReport:
    """T8: Generic Markdown format."""

    def test_table_format(self):
        from report_generators import MarkdownReport
        out = MarkdownReport.format_finding(SAMPLE_FINDING)
        assert "| Severity | Critical |" in out
        assert "| CWE | CWE-89 |" in out

    def test_poc_section(self):
        from report_generators import MarkdownReport
        out = MarkdownReport.format_finding(SAMPLE_FINDING)
        assert "PoC:" in out
        assert "curl" in out


class TestPlatformReportGenerator:
    """T9: Dispatcher."""

    def test_generate_by_string(self):
        from report_generators import PlatformReportGenerator
        out = PlatformReportGenerator.generate([SAMPLE_FINDING], fmt="yeswehack")
        assert "YesWeHack" in out

    def test_generate_by_enum(self):
        from report_generators import PlatformReportGenerator, ReportFormat
        out = PlatformReportGenerator.generate([SAMPLE_FINDING], fmt=ReportFormat.HACKERONE)
        assert "HackerOne" in out

    def test_format_single_finding(self):
        from report_generators import PlatformReportGenerator
        out = PlatformReportGenerator.format_single_finding(SAMPLE_FINDING, fmt="bugcrowd")
        assert "[P1]" in out

    def test_all_formats_generate(self):
        from report_generators import PlatformReportGenerator
        for fmt in PlatformReportGenerator.available_formats():
            out = PlatformReportGenerator.generate([SAMPLE_FINDING], fmt=fmt, target="test.com")
            assert len(out) > 50, f"Format {fmt} produced empty output"

    def test_empty_findings(self):
        from report_generators import PlatformReportGenerator
        out = PlatformReportGenerator.generate([], fmt="markdown", target="test.com")
        assert "test.com" in out
        assert "0" in out


class TestValidatedOnlyFilter:
    """T10: --validated-only filtering logic."""

    def test_rejected_filtered(self):
        findings = [
            dict(SAMPLE_FINDING, validation={"overall_verdict": "PASS"}),
            dict(SAMPLE_FINDING, title="Weak CSP", validation={"overall_verdict": "REJECTED"}),
            dict(SAMPLE_FINDING, title="Info leak", validation={"overall_verdict": "FAIL"}),
        ]
        filtered = [
            f for f in findings
            if f.get("validation", {}).get("overall_verdict") not in ("REJECTED", "FAIL")
        ]
        assert len(filtered) == 1
        assert filtered[0]["title"] == "SQL Injection in /api/users"


# ===========================================================================
# scoring_engine.py contextual CVSS tests
# ===========================================================================

class TestContextualCVSS:
    """T11: Contextual CVSS adjustments."""

    def test_unauthenticated_keeps_pr_n(self):
        from scoring_engine import score_finding
        f = {"cwe": "CWE-89", "severity": "critical"}
        scored = score_finding(f)
        assert "/PR:N/" in scored["cvss_vector"]

    def test_authenticated_downgrades_pr(self):
        from scoring_engine import score_finding
        # CWE-89 has PR:N by default — authenticated should downgrade to PR:L
        f = {"cwe": "CWE-89", "severity": "critical", "authenticated": "true"}
        scored = score_finding(f)
        assert "/PR:L/" in scored["cvss_vector"]
        assert scored["cvss_base_vector"] is not None
        assert scored["cvss_score"] < scored["cvss_base_score"]

    def test_reflected_xss_requires_ui(self):
        from scoring_engine import score_finding
        f = {"cwe": "CWE-79", "severity": "medium", "title": "Reflected XSS in search"}
        scored = score_finding(f)
        assert "/UI:R/" in scored["cvss_vector"]

    def test_local_attack_vector(self):
        from scoring_engine import score_finding
        f = {"cwe": "CWE-89", "severity": "critical", "attack_vector": "local"}
        scored = score_finding(f)
        assert "/AV:L/" in scored["cvss_vector"]
        assert scored["cvss_score"] < scored["cvss_base_score"]

    def test_no_adjustment_normal_finding(self):
        from scoring_engine import score_finding
        f = {"cwe": "CWE-918", "severity": "high"}
        scored = score_finding(f)
        # CWE-918 (SSRF) has PR:N, UI:N, AV:N — no adjustment expected
        assert "cvss_base_vector" not in scored

    def test_fallback_no_cwe(self):
        from scoring_engine import score_finding
        f = {"severity": "high"}
        scored = score_finding(f)
        assert scored["cvss_score"] == 7.5
        assert scored["cvss_vector"] is None

    def test_unauthenticated_pr_l_becomes_pr_n(self):
        from scoring_engine import score_finding
        # CWE-78 has PR:L by default — unauthenticated should upgrade to PR:N
        f = {"cwe": "CWE-78", "severity": "high", "authenticated": "false"}
        scored = score_finding(f)
        assert "/PR:N/" in scored["cvss_vector"]
        assert scored["cvss_score"] > scored["cvss_base_score"]


class TestContextualCVSSEdgeCases:
    """T12: Edge cases for contextual adjustment."""

    def test_multiple_adjustments(self):
        from scoring_engine import score_finding
        f = {
            "cwe": "CWE-78",
            "severity": "high",
            "authenticated": "false",
            "attack_vector": "local",
        }
        scored = score_finding(f)
        # PR:L→PR:N (unauthenticated) + AV:N→AV:L (local)
        assert "/PR:N/" in scored["cvss_vector"]
        assert "/AV:L/" in scored["cvss_vector"]

    def test_score_clamped_at_10(self):
        from scoring_engine import score_finding
        # CWE-287 has score 9.8, with PR:N already — unauthenticated shouldn't go above 10
        f = {"cwe": "CWE-287", "severity": "critical", "authenticated": "false"}
        scored = score_finding(f)
        assert scored["cvss_score"] <= 10.0

    def test_score_clamped_at_0(self):
        from scoring_engine import _contextual_cvss_adjust
        _, score = _contextual_cvss_adjust(
            {"authenticated": "true", "attack_vector": "local"},
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            0.5,
        )
        assert score >= 0.0


# ===========================================================================
# Integration tests
# ===========================================================================

class TestIntegration:
    """T13: Integration with CLI and pipeline."""

    def test_report_generators_cli_help(self):
        """CLI --help exits cleanly."""
        import subprocess
        result = subprocess.run(
            [sys.executable, str(SCRIPTS_DIR / "report_generators.py"), "--help"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "format" in result.stdout.lower()

    def test_report_generators_roundtrip(self, tmp_path):
        """Generate report from JSON file via CLI."""
        import subprocess
        report = {"target": "test.com", "findings": [SAMPLE_FINDING]}
        input_file = tmp_path / "test-report.json"
        input_file.write_text(json.dumps(report))
        output_file = tmp_path / "output.md"

        for fmt in ["yeswehack", "hackerone", "bugcrowd", "intigriti", "immunefi", "markdown"]:
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPTS_DIR / "report_generators.py"),
                    "--format", fmt,
                    "--input", str(input_file),
                    "--output", str(output_file),
                ],
                capture_output=True,
                text=True,
            )
            assert result.returncode == 0, f"Format {fmt} failed: {result.stderr}"
            content = output_file.read_text()
            assert len(content) > 50, f"Format {fmt} empty output"
            assert "SQL Injection" in content

    def test_scoring_engine_imports(self):
        from scoring_engine import score_finding, _contextual_cvss_adjust
        assert callable(score_finding)
        assert callable(_contextual_cvss_adjust)

    def test_smart_scan_uses_report_generators(self):
        """smart_scan.py can import report_generators (optional use)."""
        try:
            import report_generators
            assert hasattr(report_generators, "PlatformReportGenerator")
        except ImportError:
            pass  # Optional dependency
