"""Anthropic Claude provider."""

from __future__ import annotations

import os
import time
from typing import Any

from llm.base import (
    LLMMessage,
    LLMProvider,
    LLMResponse,
    ToolCall,
    ToolDefinition,
    _ensure_anthropic,
)


class ClaudeProvider(LLMProvider):
    """Anthropic Claude provider."""

    name = "claude"

    def __init__(self, model: str | None = None, api_key: str | None = None, **kwargs: Any):
        super().__init__(model, api_key, **kwargs)
        _anthropic = _ensure_anthropic()
        self._client = _anthropic.Anthropic(
            api_key=self.api_key or os.environ.get("ANTHROPIC_API_KEY"),
        )

    def _default_model(self) -> str:
        return "claude-sonnet-4-20250514"

    def _convert_tools(self, tools: list[ToolDefinition]) -> list[dict]:
        return [
            {
                "name": t.name,
                "description": t.description,
                "input_schema": t.parameters,
            }
            for t in tools
        ]

    def _convert_messages(self, messages: list[LLMMessage]) -> tuple[str, list[dict]]:
        """Convert to Anthropic message format. Returns (system, messages)."""
        system = ""
        converted = []
        for msg in messages:
            if msg.role == "system":
                system += msg.content + "\n"
            elif msg.role == "assistant":
                content: list[dict] = []
                if msg.content:
                    content.append({"type": "text", "text": msg.content})
                for tc in msg.tool_calls:
                    content.append({
                        "type": "tool_use",
                        "id": tc.id,
                        "name": tc.name,
                        "input": tc.arguments,
                    })
                converted.append({"role": "assistant", "content": content or msg.content})
            elif msg.role == "tool":
                converted.append({
                    "role": "user",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": msg.tool_call_id,
                        "content": msg.content,
                    }],
                })
            else:
                converted.append({"role": msg.role, "content": msg.content})
        return system.strip(), converted

    def chat(
        self,
        messages: list[LLMMessage],
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        system, msgs = self._convert_messages(messages)
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": msgs,
        }
        if system:
            kwargs["system"] = system
        if tools:
            kwargs["tools"] = self._convert_tools(tools)

        t0 = time.monotonic()
        response = self._client.messages.create(**kwargs)
        latency = (time.monotonic() - t0) * 1000

        content = ""
        tool_calls = []
        for block in response.content:
            if block.type == "text":
                content += block.text
            elif block.type == "tool_use":
                tool_calls.append(ToolCall(
                    id=block.id,
                    name=block.name,
                    arguments=block.input,
                ))

        self._total_requests += 1
        self._total_input_tokens += response.usage.input_tokens
        self._total_output_tokens += response.usage.output_tokens

        return LLMResponse(
            content=content,
            tool_calls=tool_calls,
            finish_reason="tool_use" if tool_calls else "stop",
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            model=self.model,
            latency_ms=latency,
        )
