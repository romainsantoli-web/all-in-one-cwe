"""Google Gemini provider — OpenAI-compatible endpoint with automatic fallback."""

from __future__ import annotations

import logging
import os
from typing import Any

from llm.base import (
    LLMMessage,
    LLMResponse,
    ToolDefinition,
    _ensure_openai,
)
from llm.providers.openai import GPTProvider

logger = logging.getLogger(__name__)


class GeminiProvider(GPTProvider):
    """Google Gemini provider via OpenAI-compatible REST endpoint.

    Falls back automatically through free-tier models on 429.
    """

    name = "gemini"

    FALLBACK_MODELS: list[str] = [
        "models/gemini-3-flash-preview",
        "models/gemini-flash-latest",
        "models/gemini-2.0-flash",
        "models/gemini-2.0-flash-001",
        "models/gemini-flash-lite-latest",
        "models/gemini-2.0-flash-lite",
        "models/gemini-2.0-flash-lite-001",
    ]

    def __init__(self, model: str | None = None, api_key: str | None = None, **kwargs: Any):
        super().__init__(
            model=model,
            api_key=api_key or os.environ.get("GEMINI_API_KEY"),
            base_url=kwargs.pop(
                "base_url",
                "https://generativelanguage.googleapis.com/v1beta/openai/",
            ),
            **kwargs,
        )

    def _default_model(self) -> str:
        return "models/gemini-3-flash-preview"

    def chat(
        self,
        messages: list[LLMMessage],
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        candidates = [self.model] + [m for m in self.FALLBACK_MODELS if m != self.model]

        last_exc: Exception | None = None
        for candidate in candidates:
            original = self.model
            self.model = candidate
            try:
                response = super().chat(
                    messages, tools=tools, temperature=temperature, max_tokens=max_tokens,
                )
                if candidate != original:
                    logger.info("GeminiProvider: fell back to %s (original: %s)", candidate, original)
                return response
            except _ensure_openai().RateLimitError as e:
                last_exc = e
                self.model = original
                logger.warning("GeminiProvider: rate-limited on %s, trying next…", candidate)
                continue
            except Exception:
                self.model = original
                raise
        raise last_exc  # type: ignore[misc]
