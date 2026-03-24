"""Provider registry — factory function to get providers by name."""

from __future__ import annotations

from typing import Any

from llm.base import LLMProvider
from llm.providers.claude import ClaudeProvider
from llm.providers.copilot import CopilotProvider
from llm.providers.copilot_pro import CopilotProProvider
from llm.providers.gemini import GeminiProvider
from llm.providers.mistral import MistralProvider
from llm.providers.openai import GPTProvider

_PROVIDERS: dict[str, type[LLMProvider]] = {
    "claude": ClaudeProvider,
    "gpt": GPTProvider,
    "openai": GPTProvider,
    "mistral": MistralProvider,
    "copilot": CopilotProvider,
    "github": CopilotProvider,
    "copilot-pro": CopilotProProvider,
    "gemini": GeminiProvider,
    "google": GeminiProvider,
}


def get_provider(name: str, **kwargs: Any) -> LLMProvider:
    """Get a provider by name. Raises KeyError if not found."""
    key = name.lower()
    if key not in _PROVIDERS:
        raise KeyError(
            f"Unknown provider '{name}'. Available: {', '.join(sorted(_PROVIDERS.keys()))}"
        )
    return _PROVIDERS[key](**kwargs)


def list_providers() -> list[str]:
    """Return sorted list of available provider names (no aliases)."""
    seen: set[int] = set()
    names: list[str] = []
    for name, cls in sorted(_PROVIDERS.items()):
        if id(cls) not in seen:
            seen.add(id(cls))
            names.append(name)
    return names
