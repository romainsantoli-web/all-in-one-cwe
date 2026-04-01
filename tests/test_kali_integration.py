#!/usr/bin/env python3
"""Tests for Kali tool integration — 8 new tools (hydra, mitmproxy, commix,
wapiti, searchsploit, masscan, recon-ng, shodan) + 2 Python scanners.

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

import importlib
import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tools" / "python-scanners"))


# ═══════════════════════════════════════════════════════════════════
# 1. Chain Rules — new Kali-related chains
# ═══════════════════════════════════════════════════════════════════

class TestChainRules:
    """Validate the 4 new chain rules added for Kali tools."""

    def setup_method(self):
        from chain_rules import CHAIN_RULES, CHAIN_INDEX, ESCALATION_INDEX
        self.rules = CHAIN_RULES
        self.index = CHAIN_INDEX
        self.esc_index = ESCALATION_INDEX

    def test_total_rules_at_least_31(self):
        assert len(self.rules) >= 31, f"Expected >=31, got {len(self.rules)}"

    def test_user_enum_brute_force_chain_exists(self):
        ids = [r["id"] for r in self.rules]
        assert "USER_ENUM→BRUTE_FORCE→ATO" in ids

    def test_default_creds_chain_exists(self):
        ids = [r["id"] for r in self.rules]
        assert "DEFAULT_CREDS→ADMIN→DATA" in ids

    def test_cmdi_rce_lateral_chain_exists(self):
        ids = [r["id"] for r in self.rules]
        assert "CMDI→RCE→LATERAL" in ids

    def test_exposed_service_cve_chain_exists(self):
        ids = [r["id"] for r in self.rules]
        assert "EXPOSED_SERVICE→CVE_EXPLOIT" in ids

    def test_no_duplicate_rule_ids(self):
        ids = [r["id"] for r in self.rules]
        assert len(ids) == len(set(ids)), f"Duplicate IDs: {[x for x in ids if ids.count(x) > 1]}"

    def test_cwe307_in_chain_index(self):
        assert "CWE-307" in self.index, "CWE-307 (brute force) should be in CHAIN_INDEX"

    def test_cwe78_in_chain_index(self):
        assert "CWE-78" in self.index, "CWE-78 (command injection) should be in CHAIN_INDEX"

    def test_new_chains_have_tools(self):
        new_ids = {
            "USER_ENUM→BRUTE_FORCE→ATO",
            "DEFAULT_CREDS→ADMIN→DATA",
            "CMDI→RCE→LATERAL",
            "EXPOSED_SERVICE→CVE_EXPLOIT",
        }
        for rule in self.rules:
            if rule["id"] in new_ids:
                for step in rule["next_steps"]:
                    assert "tools" in step and len(step["tools"]) > 0, (
                        f"Rule {rule['id']} step missing tools"
                    )


# ═══════════════════════════════════════════════════════════════════
# 2. STATE_TOOLS — new tools registered
# ═══════════════════════════════════════════════════════════════════

class TestStateTools:
    """Validate new tools in react_engine STATE_TOOLS."""

    def setup_method(self):
        from react_engine import STATE_TOOLS
        self.tools = STATE_TOOLS

    def test_brute_forcer_in_hunting(self):
        assert "brute-forcer" in self.tools["hunting"]

    def test_commix_in_hunting(self):
        assert "commix" in self.tools["hunting"]

    def test_wapiti_in_hunting(self):
        assert "wapiti" in self.tools["hunting"]

    def test_masscan_in_recon(self):
        assert "masscan" in self.tools["recon"]

    def test_recon_ng_in_recon(self):
        assert "recon-ng" in self.tools["recon"]

    def test_shodan_cli_in_recon(self):
        assert "shodan-cli" in self.tools["recon"]

    def test_osint_enricher_in_profiling(self):
        assert "osint-enricher" in self.tools["profiling"]

    def test_osint_enricher_in_recon(self):
        assert "osint-enricher" in self.tools["recon"]

    def test_mitmproxy_in_validating(self):
        assert "mitmproxy" in self.tools["validating"]


# ═══════════════════════════════════════════════════════════════════
# 3. PROFILES — new tools in medium profile
# ═══════════════════════════════════════════════════════════════════

class TestProfiles:
    """Validate smart_scan PROFILES include new tools."""

    def setup_method(self):
        from smart_scan import PROFILES
        self.profiles = PROFILES

    def test_medium_has_brute_forcer(self):
        assert "brute-forcer" in self.profiles["medium"]

    def test_medium_has_commix(self):
        assert "commix" in self.profiles["medium"]

    def test_medium_has_wapiti(self):
        assert "wapiti" in self.profiles["medium"]

    def test_medium_has_osint_enricher(self):
        assert "osint-enricher" in self.profiles["medium"]


# ═══════════════════════════════════════════════════════════════════
# 4. brute_forcer.py — unit tests
# ═══════════════════════════════════════════════════════════════════

class TestBruteForcer:
    """Test brute_forcer.py scanner functions."""

    def test_import_ok(self):
        import brute_forcer
        assert hasattr(brute_forcer, "test_default_creds")
        assert hasattr(brute_forcer, "test_rate_limiting")
        assert hasattr(brute_forcer, "test_weak_password_policy")

    def test_default_creds_constants(self):
        from brute_forcer import DEFAULT_CREDS, DEFAULT_LOGIN_ENDPOINTS
        assert len(DEFAULT_CREDS) >= 10, "Need at least 10 default credential pairs"
        assert len(DEFAULT_LOGIN_ENDPOINTS) >= 5, "Need at least 5 login endpoints"
        # All creds should be (user, pass) tuples
        for user, pwd in DEFAULT_CREDS:
            assert isinstance(user, str) and isinstance(pwd, str)

    def test_default_creds_dry_run(self):
        """Dry-run mode must produce zero findings and not make requests."""
        from brute_forcer import test_default_creds
        mock_sess = MagicMock()
        findings = test_default_creds(
            sess=mock_sess,
            target="http://example.com",
            config={},
            dry_run=True,
        )
        assert findings == []
        mock_sess.post.assert_not_called()

    def test_default_creds_success_detection(self):
        """Simulates a successful login → should produce a finding."""
        from brute_forcer import test_default_creds
        mock_sess = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"token": "eyJhb..."}'
        mock_sess.post.return_value = mock_resp

        findings = test_default_creds(
            sess=mock_sess,
            target="http://vuln.test",
            config={"login_endpoints": ["/login"]},
            dry_run=False,
        )
        assert len(findings) > 0
        assert findings[0].cwe == "CWE-798"
        assert findings[0].severity == "critical"

    def test_default_creds_failure_no_finding(self):
        """When login fails, no finding should be produced."""
        from brute_forcer import test_default_creds
        mock_sess = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.text = '{"error": "invalid credentials"}'
        mock_sess.post.return_value = mock_resp

        findings = test_default_creds(
            sess=mock_sess,
            target="http://safe.test",
            config={"login_endpoints": ["/login"]},
            dry_run=False,
        )
        assert findings == []

    def test_rate_limiting_dry_run(self):
        from brute_forcer import test_rate_limiting
        mock_sess = MagicMock()
        findings = test_rate_limiting(
            sess=mock_sess,
            target="http://example.com",
            config={},
            dry_run=True,
        )
        assert findings == []
        mock_sess.post.assert_not_called()

    def test_weak_password_policy_dry_run(self):
        from brute_forcer import test_weak_password_policy
        mock_sess = MagicMock()
        findings = test_weak_password_policy(
            sess=mock_sess,
            target="http://example.com",
            config={},
            dry_run=True,
        )
        assert findings == []


# ═══════════════════════════════════════════════════════════════════
# 5. osint_enricher.py — unit tests
# ═══════════════════════════════════════════════════════════════════

class TestOsintEnricher:
    """Test osint_enricher.py scanner functions."""

    def test_import_ok(self):
        import osint_enricher
        assert hasattr(osint_enricher, "query_shodan")
        assert hasattr(osint_enricher, "searchsploit_lookup")
        assert hasattr(osint_enricher, "parse_recon_ng_results")

    def test_shodan_no_key_skips(self):
        """Without SHODAN_API_KEY, should return empty and not crash."""
        from osint_enricher import query_shodan
        with patch.dict(os.environ, {}, clear=True):
            findings = query_shodan("example.com", {}, dry_run=False)
        assert findings == []

    def test_shodan_dry_run(self):
        from osint_enricher import query_shodan
        findings = query_shodan("example.com", {"shodan_api_key": "test"}, dry_run=True)
        assert findings == []

    def test_searchsploit_dry_run(self):
        from osint_enricher import searchsploit_lookup
        findings = searchsploit_lookup(
            tech_stack=["nginx", "apache"],
            config={},
            dry_run=True,
        )
        assert findings == []

    def test_recon_ng_no_dir_returns_empty(self):
        from osint_enricher import parse_recon_ng_results
        with patch.dict(os.environ, {"REPORTS_DIR": "/nonexistent/dir"}, clear=False):
            findings = parse_recon_ng_results(config={})
        assert findings == []


# ═══════════════════════════════════════════════════════════════════
# 6. Config files — YAML validity & required keys
# ═══════════════════════════════════════════════════════════════════

class TestConfigs:
    """Validate YAML config files for new tools."""

    def _load(self, name: str) -> dict:
        path = ROOT / "configs" / name
        assert path.exists(), f"Config file missing: {name}"
        with open(path) as f:
            return yaml.safe_load(f)

    def test_brute_forcer_config(self):
        cfg = self._load("brute-forcer-config.yaml")
        assert "login_endpoints" in cfg
        assert "credentials" in cfg
        assert len(cfg["credentials"]) >= 5

    def test_osint_enricher_config(self):
        cfg = self._load("osint-enricher-config.yaml")
        assert "expected_ports" in cfg

    def test_commix_config(self):
        cfg = self._load("commix-config.yaml")
        assert "level" in cfg or "injection_level" in cfg

    def test_recon_ng_resource(self):
        path = ROOT / "configs" / "recon-ng-resource.rc"
        assert path.exists(), "recon-ng-resource.rc missing"
        content = path.read_text()
        assert "workspaces" in content.lower() or "modules" in content.lower()


# ═══════════════════════════════════════════════════════════════════
# 7. Docker compose — new services present
# ═══════════════════════════════════════════════════════════════════

class TestDockerCompose:
    """Validate docker-compose.yml has all 10 new services."""

    def setup_method(self):
        with open(ROOT / "docker-compose.yml") as f:
            self.content = f.read()

    @pytest.mark.parametrize("service", [
        "hydra", "mitmproxy", "commix", "wapiti", "searchsploit",
        "masscan", "recon-ng", "shodan-cli", "brute-forcer", "osint-enricher",
    ])
    def test_service_defined(self, service):
        assert f"  {service}:" in self.content, f"Service {service} not in docker-compose.yml"


# ═══════════════════════════════════════════════════════════════════
# 8. Wordlists — hydra dependency
# ═══════════════════════════════════════════════════════════════════

class TestWordlists:
    """Verify wordlists exist for hydra."""

    def test_users_txt_exists(self):
        path = ROOT / "wordlists" / "users.txt"
        assert path.exists(), "wordlists/users.txt missing"
        lines = path.read_text().strip().splitlines()
        assert len(lines) >= 5, "users.txt should have at least 5 entries"

    def test_passwords_txt_exists(self):
        path = ROOT / "wordlists" / "passwords.txt"
        assert path.exists(), "wordlists/passwords.txt missing"
        lines = path.read_text().strip().splitlines()
        assert len(lines) >= 5, "passwords.txt should have at least 5 entries"


# ═══════════════════════════════════════════════════════════════════
# 9. runner.sh — new tool sections present
# ═══════════════════════════════════════════════════════════════════

class TestRunnerSh:
    """Verify runner.sh has dispatch sections for new tools."""

    def setup_method(self):
        self.content = (ROOT / "runner.sh").read_text()

    @pytest.mark.parametrize("tool", [
        "brute-forcer", "commix", "wapiti", "osint-enricher",
        "masscan", "recon-ng", "shodan-cli", "hydra", "mitmproxy",
    ])
    def test_tool_in_runner(self, tool):
        assert tool in self.content, f"Tool {tool} not dispatched in runner.sh"
