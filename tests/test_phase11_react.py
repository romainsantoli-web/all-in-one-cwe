#!/usr/bin/env python3
"""Tests for Phase 11 — ReAct engine + Safety controls.

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

import json
import os
import sys
import time
from pathlib import Path

import pytest

# Ensure scripts/ is importable
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from safety import AuditLog, Budget, CircuitBreaker, RateLimiter  # noqa: E402
from react_engine import CheckpointMode, HuntState, ReactEngine, ReactStep  # noqa: E402


# ═══════════════════════════════════════════════════
# Safety: RateLimiter
# ═══════════════════════════════════════════════════

class TestRateLimiter:
    def test_allows_under_limit(self):
        rl = RateLimiter(max_per_host=3, window_seconds=60)
        assert rl.allow("example.com") is True
        assert rl.allow("example.com") is True
        assert rl.allow("example.com") is True

    def test_blocks_over_limit(self):
        rl = RateLimiter(max_per_host=2, window_seconds=60)
        assert rl.allow("host.com") is True
        assert rl.allow("host.com") is True
        assert rl.allow("host.com") is False

    def test_separate_hosts(self):
        rl = RateLimiter(max_per_host=1, window_seconds=60)
        assert rl.allow("a.com") is True
        assert rl.allow("b.com") is True
        assert rl.allow("a.com") is False
        assert rl.allow("b.com") is False

    def test_reset_host(self):
        rl = RateLimiter(max_per_host=1, window_seconds=60)
        assert rl.allow("x.com") is True
        assert rl.allow("x.com") is False
        rl.reset("x.com")
        assert rl.allow("x.com") is True

    def test_reset_all(self):
        rl = RateLimiter(max_per_host=1, window_seconds=60)
        rl.allow("a.com")
        rl.allow("b.com")
        rl.reset()
        assert rl.allow("a.com") is True
        assert rl.allow("b.com") is True


# ═══════════════════════════════════════════════════
# Safety: CircuitBreaker
# ═══════════════════════════════════════════════════

class TestCircuitBreaker:
    def test_allows_initially(self):
        cb = CircuitBreaker(failure_threshold=3)
        assert cb.allow("host.com") is True

    def test_opens_after_threshold(self):
        cb = CircuitBreaker(failure_threshold=2, reset_timeout=1000)
        cb.record_failure("h.com")
        cb.record_failure("h.com")
        assert cb.is_open("h.com") is True
        assert cb.allow("h.com") is False

    def test_success_resets(self):
        cb = CircuitBreaker(failure_threshold=3)
        cb.record_failure("h.com")
        cb.record_failure("h.com")
        cb.record_success("h.com")
        cb.record_failure("h.com")
        # Only 1 failure since last success, should still allow
        assert cb.allow("h.com") is True

    def test_separate_hosts(self):
        cb = CircuitBreaker(failure_threshold=1, reset_timeout=1000)
        cb.record_failure("a.com")
        assert cb.is_open("a.com") is True
        assert cb.allow("b.com") is True


# ═══════════════════════════════════════════════════
# Safety: Budget
# ═══════════════════════════════════════════════════

class TestBudget:
    def test_initial_not_exceeded(self):
        b = Budget(max_steps=10)
        assert b.exceeded is False

    def test_steps_exceeded(self):
        b = Budget(max_steps=2)
        b.use_step()
        b.use_step()
        assert b.exceeded is True

    def test_tokens_exceeded(self):
        b = Budget(max_tokens=100)
        b.use_tokens(101)
        assert b.exceeded is True

    def test_remaining(self):
        b = Budget(max_steps=10, max_tokens=1000, max_time_seconds=3600)
        b.start()
        b.use_step()
        b.use_tokens(200)
        rem = b.remaining
        assert rem["steps"] == 9
        assert rem["tokens"] == 800

    def test_to_dict(self):
        b = Budget(max_steps=5)
        d = b.to_dict()
        assert "steps_used" in d
        assert "exceeded" in d
        assert d["steps_max"] == 5


# ═══════════════════════════════════════════════════
# Safety: AuditLog
# ═══════════════════════════════════════════════════

class TestAuditLog:
    def test_log_and_read(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        al = AuditLog(log_path)
        al.log("test_event", key="value")
        al.log("second_event", num=42)
        entries = al.read_last(10)
        assert len(entries) == 2
        assert entries[0]["event"] == "test_event"
        assert entries[1]["num"] == 42

    def test_read_empty(self, tmp_path):
        log_path = tmp_path / "empty.jsonl"
        al = AuditLog(log_path)
        assert al.read_last() == []

    def test_read_last_n(self, tmp_path):
        log_path = tmp_path / "many.jsonl"
        al = AuditLog(log_path)
        for i in range(20):
            al.log("evt", i=i)
        entries = al.read_last(5)
        assert len(entries) == 5
        assert entries[0]["i"] == 15


# ═══════════════════════════════════════════════════
# ReactEngine: Initialization
# ═══════════════════════════════════════════════════

class TestReactEngineInit:
    def test_valid_http_target(self):
        engine = ReactEngine(target="http://example.com")
        assert engine.target == "http://example.com"
        assert engine.domain == "example.com"

    def test_valid_https_target(self):
        engine = ReactEngine(target="https://test.example.com/path")
        assert engine.domain == "test.example.com"

    def test_invalid_scheme_raises(self):
        with pytest.raises(ValueError, match="Invalid target URL scheme"):
            ReactEngine(target="ftp://bad.com")

    def test_default_state_is_scoping(self):
        engine = ReactEngine(target="https://x.com")
        assert engine.state == HuntState.SCOPING

    def test_default_mode_is_normal(self):
        engine = ReactEngine(target="https://x.com")
        assert engine.mode == CheckpointMode.NORMAL

    def test_custom_budget(self):
        b = Budget(max_steps=10, max_time_seconds=120)
        engine = ReactEngine(target="https://x.com", budget=b)
        assert engine.budget.max_steps == 10


# ═══════════════════════════════════════════════════
# ReactEngine: State Machine
# ═══════════════════════════════════════════════════

class TestReactEngineStateMachine:
    def test_state_transitions(self):
        engine = ReactEngine(target="https://x.com")
        expected = [
            HuntState.PROFILING, HuntState.RECON, HuntState.HUNTING,
            HuntState.CHAINING, HuntState.VALIDATING, HuntState.REPORTING,
            HuntState.COMPLETE,
        ]
        for exp in expected:
            new_state = engine._next_state()
            engine.state = new_state
            assert engine.state == exp

    def test_complete_stays_complete(self):
        engine = ReactEngine(target="https://x.com")
        engine.state = HuntState.COMPLETE
        assert engine._next_state() == HuntState.COMPLETE


# ═══════════════════════════════════════════════════
# ReactEngine: Observation & Reasoning
# ═══════════════════════════════════════════════════

class TestReactEngineObserve:
    def test_observe_structure(self):
        engine = ReactEngine(target="https://x.com")
        obs = engine._observe()
        assert obs["state"] == "scoping"
        assert obs["target"] == "https://x.com"
        assert "budget" in obs
        assert "available_tools" in obs

    def test_think_scoping(self):
        engine = ReactEngine(target="https://x.com")
        obs = engine._observe()
        reasoning = engine._think(obs)
        assert "target" in reasoning.lower() or "scope" in reasoning.lower()

    def test_think_profiling_no_tech(self):
        engine = ReactEngine(target="https://x.com")
        engine.state = HuntState.PROFILING
        obs = engine._observe()
        reasoning = engine._think(obs)
        assert "tech" in reasoning.lower()


# ═══════════════════════════════════════════════════
# ReactEngine: Step Execution
# ═══════════════════════════════════════════════════

class TestReactEngineStep:
    def test_single_step(self):
        engine = ReactEngine(target="https://httpbin.org", budget=Budget(max_steps=5))
        step = engine.step()
        assert isinstance(step, ReactStep)
        assert step.step_number == 1
        assert step.state == "scoping"

    def test_budget_tracked(self):
        engine = ReactEngine(target="https://x.com", budget=Budget(max_steps=5))
        engine.step()
        engine.step()
        assert engine.budget.steps_used == 2

    def test_stuck_detection(self):
        engine = ReactEngine(target="https://x.com", budget=Budget(max_steps=20))
        engine.state = HuntState.HUNTING
        # Run multiple steps without findings
        for _ in range(5):
            engine.step()
        # Should have advanced state due to stuck detection
        assert engine.state != HuntState.HUNTING


# ═══════════════════════════════════════════════════
# ReactEngine: Finding Extraction
# ═══════════════════════════════════════════════════

class TestReactEngineFindings:
    def test_extract_from_list(self):
        engine = ReactEngine(target="https://x.com")
        output = json.dumps([{"title": "SQLi", "severity": "high"}, {"title": "XSS"}])
        findings = engine._extract_findings(output, "test-tool")
        assert len(findings) == 2
        assert findings[0]["tool"] == "test-tool"

    def test_extract_from_dict_with_findings_key(self):
        engine = ReactEngine(target="https://x.com")
        output = json.dumps({"findings": [{"title": "SSRF"}]})
        findings = engine._extract_findings(output, "ssrf-scanner")
        assert len(findings) == 1

    def test_extract_from_dict_with_vulnerabilities_key(self):
        engine = ReactEngine(target="https://x.com")
        output = json.dumps({"vulnerabilities": [{"name": "Path Traversal"}]})
        findings = engine._extract_findings(output, "nuclei")
        assert len(findings) == 1

    def test_extract_invalid_json(self):
        engine = ReactEngine(target="https://x.com")
        findings = engine._extract_findings("not json", "tool")
        assert findings == []

    def test_extract_empty_list(self):
        engine = ReactEngine(target="https://x.com")
        findings = engine._extract_findings("[]", "tool")
        assert findings == []


# ═══════════════════════════════════════════════════
# ReactEngine: Summary
# ═══════════════════════════════════════════════════

class TestReactEngineSummary:
    def test_summary_structure(self):
        engine = ReactEngine(target="https://x.com", mode=CheckpointMode.PARANOID)
        engine.findings = [{"title": "test"}]
        engine.chains = [{"id": "chain1"}]
        s = engine.get_summary()
        assert s["target"] == "https://x.com"
        assert s["mode"] == "paranoid"
        assert s["findings_count"] == 1
        assert s["chains_count"] == 1
        assert "budget" in s


# ═══════════════════════════════════════════════════
# ReactEngine: Checkpoint Logic
# ═══════════════════════════════════════════════════

class TestCheckpoint:
    def test_paranoid_checkpoints_on_new_finding(self):
        engine = ReactEngine(target="https://x.com", mode=CheckpointMode.PARANOID)
        engine._last_findings_count = 0
        engine.findings = [{"title": "new"}]
        assert engine._should_checkpoint() is True

    def test_paranoid_no_checkpoint_without_new_finding(self):
        engine = ReactEngine(target="https://x.com", mode=CheckpointMode.PARANOID)
        engine._last_findings_count = 1
        engine.findings = [{"title": "old"}]
        assert engine._should_checkpoint() is False

    def test_yolo_checkpoints_before_reporting(self):
        engine = ReactEngine(target="https://x.com", mode=CheckpointMode.YOLO)
        engine.state = HuntState.REPORTING
        assert engine._should_checkpoint() is True

    def test_yolo_no_checkpoint_during_hunting(self):
        engine = ReactEngine(target="https://x.com", mode=CheckpointMode.YOLO)
        engine.state = HuntState.HUNTING
        assert engine._should_checkpoint() is False


# ═══════════════════════════════════════════════════
# HuntState Enum
# ═══════════════════════════════════════════════════

class TestHuntState:
    def test_all_states(self):
        states = list(HuntState)
        assert len(states) == 9
        assert HuntState.SCOPING in states
        assert HuntState.COMPLETE in states

    def test_string_value(self):
        assert HuntState.SCOPING.value == "scoping"
        assert HuntState.COMPLETE.value == "complete"


# ═══════════════════════════════════════════════════
# CheckpointMode Enum
# ═══════════════════════════════════════════════════

class TestCheckpointMode:
    def test_all_modes(self):
        modes = list(CheckpointMode)
        assert len(modes) == 3

    def test_values(self):
        assert CheckpointMode.PARANOID.value == "paranoid"
        assert CheckpointMode.YOLO.value == "yolo"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
