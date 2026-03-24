"""Base classes for the LLM provider abstraction.

Ported from firm-protocol/src/firm/llm/providers.py — adapted for
security scanner context (no firm dependency, simplified for analysis-only use).
"""

from __future__ import annotations

import json
import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Lazy SDK imports — only loaded when their providers are actually instantiated
# ---------------------------------------------------------------------------
openai = None  # type: ignore[assignment]
anthropic = None  # type: ignore[assignment]
mistralai = None  # type: ignore[assignment]


def _ensure_openai():
    global openai
    if openai is None:
        import openai as _openai
        openai = _openai
    return openai


def _ensure_anthropic():
    global anthropic
    if anthropic is None:
        import anthropic as _anthropic
        anthropic = _anthropic
    return anthropic


def _ensure_mistralai():
    global mistralai
    if mistralai is None:
        import mistralai as _mistralai
        mistralai = _mistralai
    return mistralai


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class ToolCall:
    """A tool call requested by the LLM."""

    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class ToolDefinition:
    """Tool definition in provider-agnostic format."""

    name: str
    description: str
    parameters: dict[str, Any]  # JSON Schema


@dataclass
class LLMMessage:
    """A message in a conversation."""

    role: str  # "system", "user", "assistant", "tool"
    content: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_call_id: str | None = None
    name: str | None = None
    _raw: Any = None


@dataclass
class LLMResponse:
    """Response from an LLM provider."""

    content: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    finish_reason: str = "stop"
    input_tokens: int = 0
    output_tokens: int = 0
    model: str = ""
    latency_ms: float = 0.0
    raw_message: Any = None

    @property
    def has_tool_calls(self) -> bool:
        return len(self.tool_calls) > 0

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------


class LLMProvider(ABC):
    """Abstract LLM provider — all providers implement this interface."""

    name: str = "base"
    model: str = ""

    def __init__(
        self,
        model: str | None = None,
        api_key: str | None = None,
        **kwargs: Any,
    ):
        self.model = model or self._default_model()
        self.api_key = api_key
        self.config = kwargs
        self._total_input_tokens = 0
        self._total_output_tokens = 0
        self._total_requests = 0

    @abstractmethod
    def _default_model(self) -> str: ...

    @abstractmethod
    def chat(
        self,
        messages: list[LLMMessage],
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Send a chat completion request."""
        ...

    def simple_chat(self, prompt: str, **kwargs: Any) -> str:
        """Convenience: send a single user message and return text content."""
        resp = self.chat([LLMMessage(role="user", content=prompt)], **kwargs)
        return resp.content

    def get_stats(self) -> dict[str, Any]:
        """Return usage statistics."""
        return {
            "provider": self.name,
            "model": self.model,
            "total_requests": self._total_requests,
            "total_input_tokens": self._total_input_tokens,
            "total_output_tokens": self._total_output_tokens,
        }
