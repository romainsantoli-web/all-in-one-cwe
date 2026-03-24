"""GitHub Copilot provider — OpenAI-compatible endpoint (free tier)."""

from __future__ import annotations

import os
from typing import Any

from llm.providers.openai import GPTProvider


class CopilotProvider(GPTProvider):
    """GitHub Copilot/Models provider — OpenAI-compatible endpoint (free tier)."""

    name = "copilot"

    def __init__(self, model: str | None = None, api_key: str | None = None, **kwargs: Any):
        super().__init__(
            model=model,
            api_key=api_key or os.environ.get("GITHUB_TOKEN"),
            base_url=kwargs.pop("base_url", "https://models.inference.ai.azure.com"),
            **kwargs,
        )

    def _default_model(self) -> str:
        return "gpt-4o"
