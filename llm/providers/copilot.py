"""GitHub Copilot provider — uses Copilot Pro API with OAuth device flow.

Same authentication as copilot-pro but with a different default model (gpt-4o).
Falls back to GitHub Models API (models.inference.ai.azure.com) only when
GITHUB_TOKEN is set and no OAuth device flow has been completed.
"""

from __future__ import annotations

import os
from typing import Any

from llm.providers.copilot_pro import CopilotProProvider
from llm.providers.openai import GPTProvider


class CopilotProvider(CopilotProProvider):
    """GitHub Copilot provider — same API as CopilotPro, default model gpt-4o."""

    name = "copilot"

    def __init__(self, model: str | None = None, api_key: str | None = None, **kwargs: Any):
        # Check if we have an OAuth token (device flow completed)
        oauth = kwargs.get("oauth_token") or os.environ.get("COPILOT_OAUTH_TOKEN")
        if not oauth:
            # Check cached tokens
            _, oauth, _ = self._load_cached_tokens()

        if oauth:
            # Use Copilot Pro API (same as Compta)
            super().__init__(model=model, api_key=api_key, **kwargs)
        else:
            # Fallback: try GitHub Models API (requires PAT with models:read)
            token = api_key or os.environ.get("GITHUB_TOKEN")
            if not token:
                raise ValueError(
                    "Copilot requires authentication. "
                    "Use the OAuth device flow on the /llm page or set GITHUB_TOKEN."
                )
            # Skip CopilotProProvider init, use GPTProvider directly
            GPTProvider.__init__(
                self,
                model=model,
                api_key=token,
                base_url="https://models.inference.ai.azure.com",
                **kwargs,
            )

    def _default_model(self) -> str:
        return "gpt-4o"
