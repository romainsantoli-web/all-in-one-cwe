"""LLM multi-provider engine for security-all-in-one-cwe.

Supports: Claude, GPT, Copilot Pro (OAuth), Copilot, Mistral, Gemini.
Each provider implements LLMProvider ABC and is loaded lazily.

Usage:
    from llm import get_provider
    provider = get_provider("claude")  # or "gpt", "copilot-pro", etc.
    response = provider.chat("Analyze this finding...")
"""

from llm.base import LLMMessage, LLMProvider, LLMResponse, ToolCall, ToolDefinition
from llm.registry import get_provider, list_providers

__all__ = [
    "LLMProvider",
    "LLMResponse",
    "LLMMessage",
    "ToolCall",
    "ToolDefinition",
    "get_provider",
    "list_providers",
]
