#!/usr/bin/env python3
"""Safety controls for autonomous hunting — rate limiter, circuit breaker, audit log.

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import json
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger("safety")


@dataclass
class RateLimiter:
    """Sliding-window rate limiter per host."""

    max_per_host: int = 10
    window_seconds: float = 60.0
    _hits: dict[str, list[float]] = field(default_factory=lambda: defaultdict(list))

    def allow(self, host: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        self._hits[host] = [t for t in self._hits[host] if t > cutoff]
        if len(self._hits[host]) >= self.max_per_host:
            logger.warning("Rate limit reached for %s (%d/%ds)", host, self.max_per_host, self.window_seconds)
            return False
        self._hits[host].append(now)
        return True

    def reset(self, host: str | None = None) -> None:
        if host:
            self._hits.pop(host, None)
        else:
            self._hits.clear()


@dataclass
class CircuitBreaker:
    """Per-host circuit breaker — opens after consecutive failures."""

    failure_threshold: int = 5
    reset_timeout: float = 300.0
    _failures: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    _open_until: dict[str, float] = field(default_factory=dict)

    def allow(self, host: str) -> bool:
        until = self._open_until.get(host, 0.0)
        if until > 0:
            if time.monotonic() < until:
                logger.warning("Circuit open for %s — retry after %.0fs", host, until - time.monotonic())
                return False
            # Half-open: allow one attempt
            del self._open_until[host]
            self._failures[host] = 0
        return True

    def record_success(self, host: str) -> None:
        self._failures[host] = 0
        self._open_until.pop(host, None)

    def record_failure(self, host: str) -> None:
        self._failures[host] += 1
        if self._failures[host] >= self.failure_threshold:
            self._open_until[host] = time.monotonic() + self.reset_timeout
            logger.warning("Circuit OPEN for %s after %d consecutive failures", host, self._failures[host])

    def is_open(self, host: str) -> bool:
        until = self._open_until.get(host, 0.0)
        return until > 0 and time.monotonic() < until


class AuditLog:
    """Append-only JSONL audit log for all outbound actions."""

    def __init__(self, path: str | Path = "reports/.audit/hunt.jsonl"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, event: str, **kwargs: object) -> None:
        entry = {
            "timestamp": time.time(),
            "event": event,
            **kwargs,
        }
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")

    def read_last(self, n: int = 50) -> list[dict]:
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").strip().splitlines()
        result = []
        for line in lines[-n:]:
            try:
                result.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return result


@dataclass
class Budget:
    """Resource budget for autonomous hunting."""

    max_steps: int = 50
    max_time_seconds: int = 3600
    max_tokens: int = 100_000
    max_tools_parallel: int = 5

    steps_used: int = 0
    tokens_used: int = 0
    time_started: float = 0.0

    def start(self) -> None:
        self.time_started = time.monotonic()

    def use_step(self) -> None:
        self.steps_used += 1

    def use_tokens(self, n: int) -> None:
        self.tokens_used += n

    @property
    def elapsed_seconds(self) -> float:
        if self.time_started == 0:
            return 0.0
        return time.monotonic() - self.time_started

    @property
    def exceeded(self) -> bool:
        if self.steps_used >= self.max_steps:
            return True
        if self.time_started > 0 and self.elapsed_seconds >= self.max_time_seconds:
            return True
        if self.tokens_used >= self.max_tokens:
            return True
        return False

    @property
    def remaining(self) -> dict:
        return {
            "steps": max(0, self.max_steps - self.steps_used),
            "time_seconds": max(0, int(self.max_time_seconds - self.elapsed_seconds)),
            "tokens": max(0, self.max_tokens - self.tokens_used),
        }

    def to_dict(self) -> dict:
        return {
            "steps_used": self.steps_used,
            "steps_max": self.max_steps,
            "tokens_used": self.tokens_used,
            "tokens_max": self.max_tokens,
            "elapsed_seconds": round(self.elapsed_seconds, 1),
            "max_time_seconds": self.max_time_seconds,
            "exceeded": self.exceeded,
            "remaining": self.remaining,
        }
