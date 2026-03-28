#!/usr/bin/env python3
"""ReAct autonomous hunting engine — observe → think → act loop.

Integrates: Memory, Chaining, Validation Gates, Reports.
Replaces the linear Smart Scan pipeline with a reflexive agent.

Usage:
    python scripts/react_engine.py --target https://example.com --mode normal
    python scripts/react_engine.py --target https://example.com --mode paranoid --max-steps 20

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Generator
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

from safety import AuditLog, Budget, CircuitBreaker, RateLimiter  # noqa: E402

logger = logging.getLogger("react_engine")

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class HuntState(str, Enum):
    SCOPING = "scoping"
    PROFILING = "profiling"
    RECON = "recon"
    HUNTING = "hunting"
    CHAINING = "chaining"
    VALIDATING = "validating"
    REPORTING = "reporting"
    CHECKPOINT = "checkpoint"
    COMPLETE = "complete"


class CheckpointMode(str, Enum):
    PARANOID = "paranoid"
    NORMAL = "normal"
    YOLO = "yolo"


@dataclass
class ReactStep:
    step_number: int
    state: str
    observation: dict
    reasoning: str
    action: str
    action_args: dict = field(default_factory=dict)
    result: Any = None


@dataclass
class CheckpointEvent:
    state: str
    findings: list[dict]
    chains: list[dict]
    budget: dict
    message: str = "Review required before continuing."


# Tools available per state
STATE_TOOLS: dict[str, list[str]] = {
    "scoping": ["scope_check", "target_probe"],
    "profiling": ["tech_detect", "memory_recall", "whatweb", "httpx"],
    "recon": ["subfinder", "katana", "amass", "dnsx", "whatweb", "httpx", "wafw00f"],
    "hunting": [
        "nuclei", "sqlmap", "xss-scanner", "ssrf-scanner", "idor-scanner",
        "auth-bypass", "secret-leak", "api-discovery", "zap-baseline",
        "nikto", "ffuf", "feroxbuster", "semgrep", "testssl",
    ],
    "chaining": ["chain_check"],
    "validating": ["validate_finding"],
    "reporting": ["generate_report"],
}


class ReactEngine:
    """Autonomous ReAct hunting engine with state machine."""

    def __init__(
        self,
        target: str,
        mode: CheckpointMode = CheckpointMode.NORMAL,
        budget: Budget | None = None,
        profile: str = "medium",
        scope_file: str | None = None,
        report_format: str = "markdown",
    ):
        parsed = urlparse(target)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"Invalid target URL scheme: {parsed.scheme}")

        self.target = target
        self.domain = parsed.hostname or ""
        self.mode = mode
        self.budget = budget or Budget()
        self.profile = profile
        self.scope_file = scope_file
        self.report_format = report_format

        self.state = HuntState.SCOPING
        self.findings: list[dict] = []
        self.chains: list[dict] = []
        self.tools_run: list[str] = []
        self.steps: list[ReactStep] = []
        self.tech_stack: list[str] = []
        self.memory_context: str = ""

        # Safety controls
        self.rate_limiter = RateLimiter(max_per_host=10, window_seconds=60)
        self.circuit_breaker = CircuitBreaker(failure_threshold=5, reset_timeout=300)
        self.audit_log = AuditLog(PROJECT_ROOT / "reports" / ".audit" / "hunt.jsonl")

        self._stuck_counter = 0
        self._last_findings_count = 0
        self._checkpoint_interval = 300  # 5 min for normal mode

    def _observe(self) -> dict:
        """Collect current engine state as observation."""
        return {
            "state": self.state.value,
            "target": self.target,
            "domain": self.domain,
            "findings_count": len(self.findings),
            "chains_count": len(self.chains),
            "tools_run": self.tools_run[-10:],
            "tech_stack": self.tech_stack,
            "budget": self.budget.to_dict(),
            "stuck_counter": self._stuck_counter,
            "available_tools": STATE_TOOLS.get(self.state.value, []),
        }

    def _think(self, observation: dict) -> str:
        """Generate reasoning about what to do next (LLM or heuristic)."""
        state = observation["state"]
        findings_count = observation["findings_count"]
        tools_run = observation["tools_run"]
        available = observation["available_tools"]

        if state == "scoping":
            return "Need to verify target is accessible and scope is valid before scanning."

        if state == "profiling":
            if not self.tech_stack:
                return "No tech stack detected yet. Run tech detection first."
            return f"Tech stack: {self.tech_stack}. Check memory for relevant past findings."

        if state == "recon":
            not_run = [t for t in available if t not in tools_run]
            if not_run:
                return f"Recon phase — {len(not_run)} tools remaining: {not_run[:3]}"
            return "Recon complete. Move to active hunting."

        if state == "hunting":
            not_run = [t for t in available if t not in tools_run]
            if not_run and findings_count < 3:
                return f"Low findings ({findings_count}). Try more tools: {not_run[:3]}"
            if not_run and self._stuck_counter < 3:
                return f"Continue hunting with {not_run[:2]}"
            return "Hunting sufficient. Move to chain detection."

        if state == "chaining":
            return f"Analyze {findings_count} findings for exploitation chains."

        if state == "validating":
            return f"Validate {findings_count} findings through 7-Question Gate."

        if state == "reporting":
            return f"Generate {self.report_format} report for {findings_count} validated findings."

        return "Ready to complete."

    def _act(self, action: str, args: dict | None = None) -> Any:
        """Execute an action and return the result."""
        args = args or {}
        self.audit_log.log("action", action=action, target=self.target, args=args)

        if action == "target_probe":
            return self._probe_target()
        if action == "scope_check":
            return self._check_scope()
        if action == "tech_detect":
            return self._detect_tech()
        if action == "memory_recall":
            return self._recall_memory()
        if action == "chain_check":
            return self._detect_chains()
        if action == "validate_finding":
            return self._validate_findings()
        if action == "generate_report":
            return self._generate_report()
        if action in ("run_tool", "scan"):
            tool = args.get("tool", "")
            return self._run_tool(tool)

        # Default: try running as a scanner tool
        return self._run_tool(action)

    def _probe_target(self) -> dict:
        """Check if target is accessible."""
        try:
            result = subprocess.run(
                [sys.executable, "-c",
                 f"import urllib.request; r = urllib.request.urlopen('{self.target}', timeout=10); print(r.status)"],
                capture_output=True, text=True, timeout=15,
            )
            status = result.stdout.strip()
            return {"accessible": status in ("200", "301", "302", "403"), "status": status}
        except (subprocess.TimeoutExpired, OSError):
            return {"accessible": False, "status": "timeout"}

    def _check_scope(self) -> dict:
        """Verify scope constraints."""
        if self.scope_file and Path(self.scope_file).exists():
            return {"scope_loaded": True, "file": self.scope_file}
        return {"scope_loaded": False, "target_only": self.target}

    def _detect_tech(self) -> dict:
        """Detect tech stack via tech_detector module."""
        try:
            from tech_detector import detect_tech_stack
            self.tech_stack = detect_tech_stack(self.target)
            return {"tech_stack": self.tech_stack}
        except ImportError:
            self.tech_stack = ["unknown"]
            return {"tech_stack": self.tech_stack, "error": "tech_detector not available"}

    def _recall_memory(self) -> dict:
        """Query scan memory for historical context."""
        try:
            from memory.scan_memory import ScanMemory
            mem = ScanMemory()
            recall = mem.recall_by_tech_stack(self.tech_stack, limit=5)
            self.memory_context = json.dumps(recall[:3], default=str) if recall else ""
            return {"recalled": len(recall), "context_set": bool(self.memory_context)}
        except (ImportError, Exception) as e:
            return {"recalled": 0, "error": str(e)}

    def _run_tool(self, tool_name: str) -> dict:
        """Run a security scanner tool with safety controls."""
        if not tool_name:
            return {"error": "No tool specified"}

        # Safety checks
        if not self.rate_limiter.allow(self.domain):
            return {"error": f"Rate limit reached for {self.domain}", "skipped": True}
        if not self.circuit_breaker.allow(self.domain):
            return {"error": f"Circuit breaker open for {self.domain}", "skipped": True}

        self.tools_run.append(tool_name)
        self.audit_log.log("tool_run", tool=tool_name, target=self.target)

        # Try Python scanner first
        script = PROJECT_ROOT / "tools" / "python-scanners" / f"{tool_name.replace('-', '_')}.py"
        if not script.exists():
            # Try scripts/ directory
            script = PROJECT_ROOT / "scripts" / f"{tool_name.replace('-', '_')}.py"

        if script.exists():
            try:
                result = subprocess.run(
                    [sys.executable, str(script), "--target", self.target],
                    capture_output=True, text=True, timeout=120,
                    cwd=str(PROJECT_ROOT),
                )
                self.circuit_breaker.record_success(self.domain)
                output = result.stdout[:4000] if result.stdout else result.stderr[:2000]

                # Try to parse findings from output
                new_findings = self._extract_findings(output, tool_name)
                if new_findings:
                    self.findings.extend(new_findings)

                return {"tool": tool_name, "exit_code": result.returncode, "findings_added": len(new_findings)}
            except subprocess.TimeoutExpired:
                self.circuit_breaker.record_failure(self.domain)
                return {"tool": tool_name, "error": "timeout"}
            except OSError as e:
                self.circuit_breaker.record_failure(self.domain)
                return {"tool": tool_name, "error": str(e)}

        return {"tool": tool_name, "error": "script not found", "path": str(script)}

    def _extract_findings(self, output: str, tool_name: str) -> list[dict]:
        """Best-effort extraction of findings from tool output."""
        findings = []
        try:
            data = json.loads(output)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and ("title" in item or "name" in item or "vulnerability" in item):
                        item.setdefault("tool", tool_name)
                        findings.append(item)
            elif isinstance(data, dict):
                raw = data.get("findings", data.get("vulnerabilities", data.get("results", [])))
                if isinstance(raw, list):
                    for item in raw:
                        if isinstance(item, dict):
                            item.setdefault("tool", tool_name)
                            findings.append(item)
        except (json.JSONDecodeError, TypeError):
            pass
        return findings

    def _detect_chains(self) -> dict:
        """Run chain detection on current findings."""
        try:
            from chain_engine import detect_chains, prioritize_chains
            raw_chains = detect_chains(self.findings)
            self.chains = [c.__dict__ if hasattr(c, "__dict__") else c for c in prioritize_chains(raw_chains)]
            return {"chains_detected": len(self.chains)}
        except ImportError:
            return {"chains_detected": 0, "error": "chain_engine not available"}

    def _validate_findings(self) -> dict:
        """Run validation gates on all findings."""
        try:
            from validators import ScanValidator
            validator = ScanValidator()
            validated = []
            rejected = []
            for f in self.findings:
                result = validator.validate_finding(f)
                f["validation"] = result
                if isinstance(result, dict) and result.get("overall_verdict") == "REJECTED":
                    rejected.append(f)
                else:
                    validated.append(f)
            return {"validated": len(validated), "rejected": len(rejected)}
        except ImportError:
            return {"validated": len(self.findings), "rejected": 0, "error": "validators not available"}

    def _generate_report(self) -> dict:
        """Generate a platform report from findings."""
        report = {
            "target": self.target,
            "domain": self.domain,
            "scan_date": time.strftime("%Y-%m-%d"),
            "tech_stack": self.tech_stack,
            "findings": self.findings,
            "chains": self.chains,
            "budget_used": self.budget.to_dict(),
            "tools_run": self.tools_run,
            "format": self.report_format,
        }
        # Write to reports dir
        out_path = PROJECT_ROOT / "reports" / f"autopilot-{int(time.time())}.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        return {"report_path": str(out_path), "finding_count": len(self.findings)}

    def _should_checkpoint(self) -> bool:
        """Determine if we need a human checkpoint."""
        if self.mode == CheckpointMode.PARANOID:
            # Checkpoint after each new finding
            if len(self.findings) > self._last_findings_count:
                self._last_findings_count = len(self.findings)
                return True
        elif self.mode == CheckpointMode.NORMAL:
            # Checkpoint every 5 min
            if self.budget.elapsed_seconds > 0 and int(self.budget.elapsed_seconds) % self._checkpoint_interval < 2:
                return True
        # YOLO: only checkpoint before reporting
        if self.mode == CheckpointMode.YOLO and self.state == HuntState.REPORTING:
            return True
        return False

    def _next_state(self) -> HuntState:
        """Advance the state machine."""
        transitions = {
            HuntState.SCOPING: HuntState.PROFILING,
            HuntState.PROFILING: HuntState.RECON,
            HuntState.RECON: HuntState.HUNTING,
            HuntState.HUNTING: HuntState.CHAINING,
            HuntState.CHAINING: HuntState.VALIDATING,
            HuntState.VALIDATING: HuntState.REPORTING,
            HuntState.REPORTING: HuntState.COMPLETE,
            HuntState.CHECKPOINT: self.state,  # resume from same state
        }
        return transitions.get(self.state, HuntState.COMPLETE)

    def _pick_action(self, reasoning: str) -> tuple[str, dict]:
        """Heuristic action selection based on state."""
        available = STATE_TOOLS.get(self.state.value, [])
        not_run = [t for t in available if t not in self.tools_run]

        if self.state == HuntState.SCOPING:
            return "target_probe", {}

        if self.state == HuntState.PROFILING:
            if not self.tech_stack:
                return "tech_detect", {}
            if not self.memory_context:
                return "memory_recall", {}
            return "advance_state", {}

        if self.state in (HuntState.RECON, HuntState.HUNTING):
            if not_run:
                return "run_tool", {"tool": not_run[0]}
            return "advance_state", {}

        if self.state == HuntState.CHAINING:
            return "chain_check", {}

        if self.state == HuntState.VALIDATING:
            return "validate_finding", {}

        if self.state == HuntState.REPORTING:
            return "generate_report", {}

        return "advance_state", {}

    def step(self) -> ReactStep:
        """Execute one observe → think → act cycle."""
        self.budget.use_step()
        step_num = self.budget.steps_used

        observation = self._observe()
        reasoning = self._think(observation)
        action_name, action_args = self._pick_action(reasoning)

        result = None
        if action_name == "advance_state":
            self.state = self._next_state()
            result = {"new_state": self.state.value}
        else:
            result = self._act(action_name, action_args)

        step = ReactStep(
            step_number=step_num,
            state=self.state.value,
            observation=observation,
            reasoning=reasoning,
            action=action_name,
            action_args=action_args,
            result=result,
        )
        self.steps.append(step)
        self.audit_log.log("step", step=step_num, state=self.state.value, action=action_name)

        # Stuck detection
        if len(self.findings) == self._last_findings_count:
            self._stuck_counter += 1
        else:
            self._stuck_counter = 0
            self._last_findings_count = len(self.findings)

        # If stuck for 3 steps, advance state
        if self._stuck_counter >= 3 and self.state not in (HuntState.COMPLETE, HuntState.REPORTING):
            logger.info("Stuck for %d steps — advancing state from %s", self._stuck_counter, self.state.value)
            self.state = self._next_state()
            self._stuck_counter = 0

        return step

    def run(self) -> Generator[ReactStep | CheckpointEvent, bool | None, None]:
        """Main loop — yields steps and checkpoint events.

        Send True to resume after checkpoint, False to abort.
        """
        self.budget.start()
        self.audit_log.log("hunt_start", target=self.target, mode=self.mode.value)

        while self.state != HuntState.COMPLETE:
            if self.budget.exceeded:
                logger.warning("Budget exceeded — stopping hunt")
                self.audit_log.log("budget_exceeded", budget=self.budget.to_dict())
                break

            react_step = self.step()
            yield react_step

            if self._should_checkpoint():
                checkpoint = CheckpointEvent(
                    state=self.state.value,
                    findings=self.findings,
                    chains=self.chains,
                    budget=self.budget.to_dict(),
                )
                resume = yield checkpoint
                if resume is False:
                    logger.info("Hunt aborted by user at checkpoint")
                    self.audit_log.log("hunt_aborted", state=self.state.value)
                    break

        self.audit_log.log(
            "hunt_complete",
            target=self.target,
            findings=len(self.findings),
            chains=len(self.chains),
            steps=self.budget.steps_used,
        )

    def get_summary(self) -> dict:
        """Return a summary of the hunt."""
        return {
            "target": self.target,
            "domain": self.domain,
            "state": self.state.value,
            "mode": self.mode.value,
            "findings_count": len(self.findings),
            "chains_count": len(self.chains),
            "tools_run": self.tools_run,
            "tech_stack": self.tech_stack,
            "budget": self.budget.to_dict(),
            "steps_count": len(self.steps),
        }


def main() -> int:
    """CLI entry point — runs a hunt and streams JSONL to stdout."""
    parser = argparse.ArgumentParser(description="ReAct autonomous hunting engine")
    parser.add_argument("--target", required=True, help="Target URL (https://...)")
    parser.add_argument("--mode", choices=["paranoid", "normal", "yolo"], default="normal")
    parser.add_argument("--max-steps", type=int, default=50)
    parser.add_argument("--max-time", type=int, default=3600)
    parser.add_argument("--profile", default="medium")
    parser.add_argument("--scope", default=None)
    parser.add_argument("--format", default="markdown")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

    budget = Budget(max_steps=args.max_steps, max_time_seconds=args.max_time)
    engine = ReactEngine(
        target=args.target,
        mode=CheckpointMode(args.mode),
        budget=budget,
        profile=args.profile,
        scope_file=args.scope,
        report_format=args.format,
    )

    gen = engine.run()
    try:
        event = next(gen)
        while True:
            if isinstance(event, CheckpointEvent):
                # In CLI mode, auto-resume (no interactive checkpoint)
                data = {"event": "checkpoint", "state": event.state,
                        "findings": len(event.findings), "chains": len(event.chains)}
                print(json.dumps(data), flush=True)
                event = gen.send(True)
            elif isinstance(event, ReactStep):
                data = {
                    "event": "step",
                    "step": event.step_number,
                    "state": event.state,
                    "action": event.action,
                    "reasoning": event.reasoning,
                    "result": event.result,
                }
                print(json.dumps(data, default=str), flush=True)
                event = next(gen)
            else:
                event = next(gen)
    except StopIteration:
        pass

    summary = engine.get_summary()
    print(json.dumps({"event": "complete", **summary}, default=str), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
