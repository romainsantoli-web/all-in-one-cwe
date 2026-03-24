"""Mistral AI provider."""

from __future__ import annotations

import json
import os
import time
from typing import Any

from llm.base import (
    LLMMessage,
    LLMProvider,
    LLMResponse,
    ToolCall,
    ToolDefinition,
    _ensure_mistralai,
)


class MistralProvider(LLMProvider):
    """Mistral AI provider."""

    name = "mistral"

    def __init__(self, model: str | None = None, api_key: str | None = None, **kwargs: Any):
        super().__init__(model, api_key, **kwargs)
        _mistral = _ensure_mistralai()
        self._client = _mistral.Mistral(
            api_key=self.api_key or os.environ.get("MISTRAL_API_KEY"),
        )

    def _default_model(self) -> str:
        return "mistral-large-latest"

    def _convert_tools(self, tools: list[ToolDefinition]) -> list[dict]:
        return [
            {
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.parameters,
                },
            }
            for t in tools
        ]

    def _convert_messages(self, messages: list[LLMMessage]) -> list[dict]:
        converted = []
        for msg in messages:
            if msg.role == "tool":
                converted.append({
                    "role": "tool",
                    "content": msg.content,
                    "tool_call_id": msg.tool_call_id,
                })
            elif msg.role == "assistant" and msg.tool_calls:
                tc_list = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.name,
                            "arguments": json.dumps(tc.arguments),
                        },
                    }
                    for tc in msg.tool_calls
                ]
                converted.append({
                    "role": "assistant",
                    "content": msg.content or "",
                    "tool_calls": tc_list,
                })
            else:
                converted.append({"role": msg.role, "content": msg.content})
        return converted

    def chat(
        self,
        messages: list[LLMMessage],
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": self._convert_messages(messages),
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if tools:
            kwargs["tools"] = self._convert_tools(tools)

        t0 = time.monotonic()
        response = self._client.chat.complete(**kwargs)
        latency = (time.monotonic() - t0) * 1000

        choice = response.choices[0]
        content = choice.message.content or ""
        tool_calls = []
        if choice.message.tool_calls:
            for tc in choice.message.tool_calls:
                tool_calls.append(ToolCall(
                    id=tc.id,
                    name=tc.function.name,
                    arguments=json.loads(tc.function.arguments)
                    if isinstance(tc.function.arguments, str)
                    else tc.function.arguments,
                ))

        usage = response.usage
        self._total_requests += 1
        self._total_input_tokens += usage.prompt_tokens if usage else 0
        self._total_output_tokens += usage.completion_tokens if usage else 0

        return LLMResponse(
            content=content,
            tool_calls=tool_calls,
            finish_reason=choice.finish_reason or "stop",
            input_tokens=usage.prompt_tokens if usage else 0,
            output_tokens=usage.completion_tokens if usage else 0,
            model=self.model,
            latency_ms=latency,
        )
