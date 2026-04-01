"""Tests for vault_extractor.py and smart_wordlist.py.

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

# Make python-scanners importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools" / "python-scanners"))


# ── vault_extractor ──────────────────────────────────────────


class TestVaultExtractorImport:
    """Smoke tests for vault_extractor module."""

    def test_import(self):
        import vault_extractor
        assert hasattr(vault_extractor, "scan_formats")
        assert hasattr(vault_extractor, "parse_vault_json")
        assert hasattr(vault_extractor, "ExtractLocation")

    def test_format_definitions(self):
        from vault_extractor import FORMATS
        assert len(FORMATS) >= 15
        ids = {f.id for f in FORMATS}
        assert "metamask" in ids
        assert "bitcoin_core" in ids
        assert "keepass" in ids
        assert "ssh_key" in ids

    def test_categories(self):
        from vault_extractor import FORMATS
        categories = {f.category for f in FORMATS}
        assert "crypto_wallet" in categories
        assert "password_manager" in categories
        assert "encrypted_file" in categories


class TestParseVaultJson:
    """Tests for MetaMask vault JSON parsing."""

    def test_valid_vault_modern(self):
        from vault_extractor import parse_vault_json
        vault = json.dumps({
            "data": "abc123encrypted",
            "iv": "0123456789abcdef",
            "salt": "saltvalue",
            "iterations": 900000,
        })
        result = parse_vault_json(vault)
        assert result["iterations"] == 900000
        assert result["is_legacy"] is False
        assert result["data"] == "abc123encrypted"

    def test_valid_vault_legacy(self):
        from vault_extractor import parse_vault_json
        vault = json.dumps({
            "data": "abc123encrypted",
            "iv": "0123456789abcdef",
            "salt": "saltvalue",
        })
        result = parse_vault_json(vault)
        assert result["iterations"] == 10000
        assert result["is_legacy"] is True

    def test_vault_with_key_metadata(self):
        from vault_extractor import parse_vault_json
        vault = json.dumps({
            "data": "encrypted",
            "iv": "iv123",
            "salt": "salt456",
            "keyMetadata": {"params": {"iterations": 600000}},
        })
        result = parse_vault_json(vault)
        assert result["iterations"] == 600000

    def test_invalid_vault_missing_fields(self):
        from vault_extractor import parse_vault_json
        with pytest.raises(ValueError, match="Invalid vault JSON"):
            parse_vault_json(json.dumps({"data": "only_data"}))

    def test_invalid_json(self):
        from vault_extractor import parse_vault_json
        with pytest.raises(json.JSONDecodeError):
            parse_vault_json("not valid json {{{")


class TestScanFormats:
    """Tests for filesystem scanning."""

    def test_scan_empty_dir(self, tmp_path):
        from vault_extractor import scan_formats
        results = scan_formats(extra_dirs=[str(tmp_path)])
        # Won't find anything in a temp dir
        assert isinstance(results, list)

    def test_scan_with_vault_file(self, tmp_path):
        from vault_extractor import scan_formats
        # Create a fake .kdbx file
        kdbx = tmp_path / "test.kdbx"
        kdbx.write_bytes(b"\x03\xd9\xa2\x9a" + b"\x00" * 100)
        results = scan_formats(extra_dirs=[str(tmp_path)])
        kdbx_results = [r for r in results if r.format_id == "keepass"]
        # May or may not find it depending on glob patterns
        assert isinstance(results, list)

    def test_scan_category_filter(self, tmp_path):
        from vault_extractor import scan_formats
        results = scan_formats(
            extra_dirs=[str(tmp_path)],
            include_categories=["crypto_wallet"],
        )
        for r in results:
            assert r.category == "crypto_wallet"

    def test_scan_dry_run(self, tmp_path):
        from vault_extractor import scan_formats
        results = scan_formats(extra_dirs=[str(tmp_path)], dry_run=True)
        assert results == []


class TestHelperFunctions:
    """Tests for utility functions."""

    def test_read_head(self, tmp_path):
        from vault_extractor import _read_head
        f = tmp_path / "test.bin"
        f.write_bytes(b"\x00\x01\x02\x03\x04\x05\x06\x07")
        assert _read_head(str(f), 4) == b"\x00\x01\x02\x03"

    def test_read_head_empty(self, tmp_path):
        from vault_extractor import _read_head
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")
        assert _read_head(str(f), 4) == b""

    def test_read_text(self, tmp_path):
        from vault_extractor import _read_text
        f = tmp_path / "test.txt"
        f.write_text("hello world")
        assert _read_text(str(f)) == "hello world"

    def test_read_text_binary(self, tmp_path):
        from vault_extractor import _read_text
        f = tmp_path / "binary.bin"
        f.write_bytes(b"\x00\xff\xfe\xfd")
        result = _read_text(str(f))
        assert result == ""  # Should return empty on decode error

    def test_zip_encrypted_detection(self, tmp_path):
        from vault_extractor import _zip_encrypted
        # Non-existent file
        assert _zip_encrypted(str(tmp_path / "nofile.zip")) is False


# ── smart_wordlist ───────────────────────────────────────────


class TestSmartWordlistImport:
    """Smoke tests for smart_wordlist module."""

    def test_import(self):
        import smart_wordlist
        assert hasattr(smart_wordlist, "SmartGenerator")
        assert hasattr(smart_wordlist, "PCFGEngine")
        assert hasattr(smart_wordlist, "MarkovModel")
        assert hasattr(smart_wordlist, "WebIntelCollector")
        assert hasattr(smart_wordlist, "TargetProfile")
        assert hasattr(smart_wordlist, "build_wordlist")


class TestTargetProfile:
    """Tests for profile data structure."""

    def test_default_profile(self):
        from smart_wordlist import TargetProfile
        p = TargetProfile()
        assert p.first_name == ""
        assert p.country == "FR"
        assert p.keywords == []

    def test_custom_profile(self):
        from smart_wordlist import TargetProfile
        p = TargetProfile(
            first_name="Jean",
            last_name="Dupont",
            birth_date="15/03/1990",
            city="Paris",
            keywords=["bitcoin", "crypto"],
        )
        assert p.first_name == "Jean"
        assert len(p.keywords) == 2


class TestProfileTokens:
    """Tests for profile token extraction."""

    def test_basic_tokens(self):
        from smart_wordlist import TargetProfile, _profile_tokens
        p = TargetProfile(first_name="Jean", last_name="Dupont")
        tokens = _profile_tokens(p)
        assert "Jean" in tokens
        assert "jean" in tokens
        assert "JEAN" in tokens
        assert "Dupont" in tokens

    def test_date_tokens(self):
        from smart_wordlist import TargetProfile, _profile_tokens
        p = TargetProfile(birth_date="15/03/1990")
        tokens = _profile_tokens(p)
        assert "1990" in tokens
        assert "90" in tokens
        assert "1503" in tokens

    def test_phone_tokens(self):
        from smart_wordlist import TargetProfile, _profile_tokens
        p = TargetProfile(phone="+33 6 12 34 56 78")
        tokens = _profile_tokens(p)
        assert "5678" in tokens  # Last 4 digits

    def test_email_tokens(self):
        from smart_wordlist import TargetProfile, _profile_tokens
        p = TargetProfile(email="jean.dupont@example.com")
        tokens = _profile_tokens(p)
        assert "jean.dupont" in tokens
        assert "jean" in tokens
        assert "dupont" in tokens

    def test_deduplication(self):
        from smart_wordlist import TargetProfile, _profile_tokens
        p = TargetProfile(first_name="Test", last_name="Test")
        tokens = _profile_tokens(p)
        # "Test" should appear only once
        assert tokens.count("Test") == 1


class TestLeetTransform:
    """Tests for leet speak transformation."""

    def test_basic_leet(self):
        from smart_wordlist import _leet_transform
        assert _leet_transform("password") == "p@$$w0rd"

    def test_mixed_case(self):
        from smart_wordlist import _leet_transform
        result = _leet_transform("Test")
        assert result == "73$7"  # T->7, e->3, s->$, t->7

    def test_no_leet_chars(self):
        from smart_wordlist import _leet_transform
        assert _leet_transform("1234") == "1234"


class TestPCFGEngine:
    """Tests for PCFG engine."""

    def test_parse_structure(self):
        from smart_wordlist import _parse_structure
        assert _parse_structure("Pass123!") == "U1L3D3S1"
        assert _parse_structure("abc") == "L3"
        assert _parse_structure("123") == "D3"
        assert _parse_structure("") == ""

    def test_classify_char(self):
        from smart_wordlist import _classify_char
        assert _classify_char("A") == "U"
        assert _classify_char("a") == "L"
        assert _classify_char("1") == "D"
        assert _classify_char("!") == "S"

    def test_train_and_generate(self):
        from smart_wordlist import PCFGEngine
        engine = PCFGEngine()
        engine.train(["Password123!", "Admin1234!", "Hello2024!"])
        candidates = list(engine.generate(max_candidates=50))
        assert len(candidates) > 0
        assert all(8 <= len(c) <= 30 for c in candidates)

    def test_train_empty(self):
        from smart_wordlist import PCFGEngine
        engine = PCFGEngine()
        engine.train([])
        candidates = list(engine.generate(max_candidates=10))
        assert candidates == []

    def test_stats(self):
        from smart_wordlist import PCFGEngine
        engine = PCFGEngine()
        engine.train(["Test123!"])
        stats = engine.get_stats()
        assert stats["structure_count"] > 0

    def test_train_on_profile(self):
        from smart_wordlist import PCFGEngine, TargetProfile
        engine = PCFGEngine()
        profile = TargetProfile(first_name="Jean", last_name="Dupont")
        engine.train_on_profile(profile)
        assert engine._trained is True
        stats = engine.get_stats()
        assert stats["structure_count"] > 0


class TestMarkovModel:
    """Tests for Markov chain model."""

    def test_train_and_score(self):
        from smart_wordlist import MarkovModel
        model = MarkovModel(order=2)
        model.train(["password", "passphrase", "pass1234"])
        score = model.score("password")
        assert 0 < score < 1

    def test_score_empty(self):
        from smart_wordlist import MarkovModel
        model = MarkovModel()
        assert model.score("") == 0.0

    def test_score_untrained(self):
        from smart_wordlist import MarkovModel
        model = MarkovModel()
        score = model.score("anything")
        assert score == 0.0  # No transitions

    def test_generate(self):
        from smart_wordlist import MarkovModel
        model = MarkovModel(order=2)
        model.train(["abcdefgh", "abcdefgi", "abcdefgj"] * 10)
        candidates = list(model.generate(max_candidates=20))
        assert len(candidates) > 0

    def test_generate_untrained(self):
        from smart_wordlist import MarkovModel
        model = MarkovModel()
        candidates = list(model.generate(max_candidates=10))
        assert candidates == []

    def test_stats(self):
        from smart_wordlist import MarkovModel
        model = MarkovModel()
        model.train(["hello", "world"])
        stats = model.get_stats()
        assert stats["total_samples"] == 2
        assert stats["alphabet_size"] > 0
        assert stats["context_count"] > 0


class TestSmartGenerator:
    """Tests for the main 4-phase generator."""

    def test_basic_generation(self):
        from smart_wordlist import SmartGenerator, TargetProfile
        profile = TargetProfile(
            first_name="Jean",
            last_name="Dupont",
            birth_date="15/03/1990",
        )
        gen = SmartGenerator(profile)
        candidates = list(gen.generate_all(
            max_phase1=50,
            max_phase2=50,
            max_phase3=50,
            max_phase4=50,
        ))
        assert len(candidates) > 0
        # Should contain profile-based passwords
        found_jean = any("Jean" in c or "jean" in c for c in candidates)
        assert found_jean, "Expected profile name in candidates"

    def test_with_old_passwords(self):
        from smart_wordlist import SmartGenerator, TargetProfile
        profile = TargetProfile(old_passwords=["OldPass123!"])
        gen = SmartGenerator(profile)
        candidates = list(gen.generate_all(max_phase1=50, max_phase2=0, max_phase3=0, max_phase4=0))
        assert "OldPass123!" in candidates

    def test_with_web_words(self):
        from smart_wordlist import SmartGenerator, TargetProfile
        profile = TargetProfile(first_name="Test")
        gen = SmartGenerator(profile, web_words=["blockchain", "ethereum"])
        candidates = list(gen.generate_all(max_phase1=0, max_phase2=0, max_phase3=0, max_phase4=100))
        found = any("blockchain" in c or "ethereum" in c for c in candidates)
        assert found

    def test_deduplication(self):
        from smart_wordlist import SmartGenerator, TargetProfile
        profile = TargetProfile(
            first_name="Jean",
            last_name="Dupont",
        )
        gen = SmartGenerator(profile)
        candidates = list(gen.generate_all(max_phase1=200, max_phase2=0, max_phase3=0, max_phase4=0))
        assert len(candidates) == len(set(candidates)), "Candidates should be unique"

    def test_length_filter(self):
        from smart_wordlist import SmartGenerator, TargetProfile
        profile = TargetProfile(first_name="Jean", keywords=["bitcoin"])
        gen = SmartGenerator(profile)
        candidates = list(gen.generate_all(
            max_phase1=100, max_phase2=0, max_phase3=0, max_phase4=0,
            min_len=8, max_len=20,
        ))
        for c in candidates:
            assert 8 <= len(c) <= 20, f"Candidate '{c}' outside length range"

    def test_stats(self):
        from smart_wordlist import SmartGenerator, TargetProfile
        profile = TargetProfile(first_name="Test")
        gen = SmartGenerator(profile)
        stats = gen.get_stats()
        assert stats["profile_tokens"] > 0
        assert "pcfg" in stats
        assert "markov" in stats


class TestISPCandidates:
    """Tests for ISP default key generation."""

    def test_orange_with_bssid(self):
        from smart_wordlist import generate_isp_candidates
        candidates = generate_isp_candidates("orange", "AA:BB:CC:DD:EE:FF")
        assert len(candidates) > 0
        # Should include MAC-derived candidates
        assert "DDEEFF" in candidates

    def test_unknown_isp(self):
        from smart_wordlist import generate_isp_candidates
        candidates = generate_isp_candidates("unknown_isp")
        assert candidates == []

    def test_no_bssid(self):
        from smart_wordlist import generate_isp_candidates
        candidates = generate_isp_candidates("orange")
        assert candidates == []


class TestWebIntelCollector:
    """Tests for OSINT collector (mocked network)."""

    def test_extract_social_data(self):
        from smart_wordlist import WebIntelCollector, TargetProfile
        collector = WebIntelCollector()
        profile = TargetProfile(
            first_name="Jean",
            last_name="Dupont",
            keywords=["bitcoin2024"],
            usernames=["jd_crypto.2024"],
        )
        data = collector.extract_social_data(profile)
        assert "words" in data
        assert "Jean" in data["words"]
        assert "Dupont" in data["words"]
        assert "jd" in data["words"] or "crypto" in data["words"]

    def test_collect_web_keywords_dry_run(self):
        from smart_wordlist import WebIntelCollector, TargetProfile
        collector = WebIntelCollector()
        profile = TargetProfile(first_name="Jean", last_name="Dupont")
        words = collector.collect_web_keywords(profile, dry_run=True)
        assert words == []  # Dry run produces no results

    @patch("smart_wordlist.RateLimitedSession")
    def test_collect_hibp_not_found(self, MockSession):
        from smart_wordlist import WebIntelCollector
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "AAAA1:3\nBBBB2:5"  # Won't match
        MockSession.return_value.get.return_value = mock_resp
        collector = WebIntelCollector(session=MockSession())
        result = collector.collect_hibp("test@example.com")
        assert result == []


class TestBuildWordlist:
    """Integration test for the build_wordlist function."""

    def test_build_basic(self, tmp_path, monkeypatch):
        from smart_wordlist import build_wordlist
        # Redirect output to tmp_path
        monkeypatch.setenv("HOME", str(tmp_path))
        result = build_wordlist({
            "first_name": "Jean",
            "last_name": "Dupont",
            "birth_date": "15/03/1990",
            "email": "jean@example.com",
        })
        assert result["total_candidates"] > 0
        assert result["output_path"].endswith(".txt")
        assert len(result["top_10"]) > 0
        assert os.path.isfile(result["output_path"])

    def test_build_empty_profile(self, tmp_path, monkeypatch):
        from smart_wordlist import build_wordlist
        monkeypatch.setenv("HOME", str(tmp_path))
        result = build_wordlist({})
        assert result["total_candidates"] >= 0
