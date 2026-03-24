"""Prefect task: run a Docker Compose service as a scan tool."""

from __future__ import annotations

import json
import logging
import os
import subprocess
from pathlib import Path

from prefect import task

from orchestrator.config import RETRY_DEFAULTS, TOOL_META

logger = logging.getLogger("orchestrator.docker_task")

# ---------------------------------------------------------------------------
# Finding dataclass (lightweight, no external deps)
# ---------------------------------------------------------------------------

class ScanResult:
    """Holds the output of a single tool run."""

    __slots__ = ("tool", "ok", "findings", "returncode", "stderr")

    def __init__(
        self,
        tool: str,
        ok: bool,
        findings: list[dict] | None = None,
        returncode: int = 0,
        stderr: str = "",
    ):
        self.tool = tool
        self.ok = ok
        self.findings = findings or []
        self.returncode = returncode
        self.stderr = stderr

    def has_cwe(self, cwe_id: str) -> bool:
        return any(
            cwe_id in str(f.get("cwe", "")) or cwe_id in str(f.get("cwe_id", ""))
            for f in self.findings
        )


def _should_run(tool: str, scan_ctx: dict) -> bool:
    """Check if a tool should run based on context (target/domain/code/etc.)."""
    meta = TOOL_META.get(tool, {})

    # --only / --skip filtering
    only = scan_ctx.get("only")
    skip = scan_ctx.get("skip")
    if only:
        only_set = {t.strip() for t in only.split(",")}
        if tool not in only_set:
            return False
    if skip:
        skip_set = {t.strip() for t in skip.split(",")}
        if tool in skip_set:
            return False

    # --full flag gating
    if meta.get("flag") == "full" and not scan_ctx.get("full", False):
        return False

    # Context requirements (target, domain, code, repo, binary, etc.)
    requires = meta.get("requires")
    if requires == "target" and not scan_ctx.get("target"):
        return False
    if requires == "domain" and not scan_ctx.get("domain"):
        return False
    if requires == "code":
        code = scan_ctx.get("code", ".")
        if not code or code == "." or not Path(code).is_dir():
            return False
    if requires == "repo":
        repo = scan_ctx.get("repo", ".")
        if not repo or repo == "." or not Path(repo).is_dir():
            return False
    if requires == "binary" and not scan_ctx.get("binary"):
        return False
    if requires == "bin_dir":
        bd = scan_ctx.get("bin_dir", ".")
        if not bd or bd == ".":
            return False
    if requires == "image":
        img = scan_ctx.get("image", "alpine:latest")
        if not img or img == "alpine:latest":
            return False

    # Env var requirements (any one of the listed vars must be set)
    env_requires = meta.get("env_requires", [])
    if env_requires and not any(os.environ.get(k) for k in env_requires):
        return False

    # File requirements
    file_requires = meta.get("file_requires")
    if file_requires and not Path(file_requires).exists():
        return False

    return True


def _build_docker_cmd(tool: str, scan_ctx: dict) -> list[str]:
    """Build the docker compose run command for a tool."""
    meta = TOOL_META.get(tool, {})
    profile = meta.get("profile")

    cmd = ["docker", "compose"]
    if profile:
        cmd += ["--profile", profile]
    cmd += ["run", "--rm", tool]
    return cmd


@task(
    retries=RETRY_DEFAULTS["max_retries"],
    retry_delay_seconds=RETRY_DEFAULTS["retry_delay_seconds"],
    retry_jitter_factor=RETRY_DEFAULTS["retry_jitter_factor"],
    log_prints=True,
)
def run_docker_tool(tool: str, scan_ctx: dict) -> ScanResult:
    """Execute a Docker Compose service and capture its output."""

    if not _should_run(tool, scan_ctx):
        logger.info("Skipping %s (filtered or missing prereqs)", tool)
        return ScanResult(tool=tool, ok=True)

    if scan_ctx.get("dry_run"):
        logger.info("[DRY-RUN] Would run: %s", tool)
        return ScanResult(tool=tool, ok=True)

    cmd = _build_docker_cmd(tool, scan_ctx)
    logger.info("Running: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=scan_ctx.get("timeout", 1800),  # 30min default
            cwd=scan_ctx.get("workdir", "."),
        )
        ok = result.returncode == 0

        # Try to load findings from the tool's report directory
        findings = _load_findings(tool)

        if not ok:
            logger.warning("%s exited with code %d", tool, result.returncode)

        return ScanResult(
            tool=tool,
            ok=ok,
            findings=findings,
            returncode=result.returncode,
            stderr=result.stderr[-2000:] if result.stderr else "",
        )

    except subprocess.TimeoutExpired:
        logger.error("%s timed out after %ds", tool, scan_ctx.get("timeout", 1800))
        return ScanResult(tool=tool, ok=False, returncode=-1, stderr="Timeout")


def _load_findings(tool: str) -> list[dict]:
    """Try to load JSON findings from reports/<tool>/scan-latest.json."""
    report_dir = Path("reports") / tool
    candidates = [
        report_dir / "scan-latest.json",
        report_dir / f"{tool}-results.json",
    ]
    for path in candidates:
        if path.exists():
            try:
                data = json.loads(path.read_text())
                if isinstance(data, list):
                    return data
                if isinstance(data, dict) and "findings" in data:
                    return data["findings"]
            except (json.JSONDecodeError, OSError):
                pass
    # Also try JSONL (nuclei format)
    jsonl = report_dir / "scan-latest.jsonl"
    if jsonl.exists():
        findings = []
        try:
            for line in jsonl.read_text().splitlines():
                line = line.strip()
                if line:
                    findings.append(json.loads(line))
        except (json.JSONDecodeError, OSError):
            pass
        return findings
    return []
