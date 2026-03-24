"""OpenAI GPT provider."""

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
    _ensure_openai,
)


class GPTProvider(LLMProvider):
    """OpenAI GPT provider."""

    name = "gpt"

    def __init__(self, model: str | None = None, api_key: str | None = None, **kwargs: Any):
        super().__init__(model, api_key, **kwargs)
        self._client = _ensure_openai().OpenAI(
            api_key=self.api_key or os.environ.get("OPENAI_API_KEY"),
            base_url=kwargs.get("base_url"),
        )

    def _default_model(self) -> str:
        return "gpt-4o"

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
            if msg._raw is not None:
                converted.append(msg._raw)
                continue
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
                    "content": msg.content or None,
                    "tool_calls": tc_list,
                })
            else:
                converted.append({"role": msg.role, "content": msg.content})
        return converted

    # Models requiring max_completion_tokens instead of max_tokens (and no temperature)
    _COMPLETION_TOKENS_MODELS = (
        "o1", "o1-mini", "o1-preview", "o3", "o3-mini", "o3-pro",
        "o4-mini", "gpt-5", "gpt-5-mini", "gpt-5-nano",
    )

    def chat(
        self,
        messages: list[LLMMessage],
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        use_completion_tokens = any(
            self.model.startswith(p) for p in self._COMPLETION_TOKENS_MODELS
        )
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": self._convert_messages(messages),
        }
        if use_completion_tokens:
            kwargs["max_completion_tokens"] = max_tokens
        else:
            kwargs["temperature"] = temperature
            kwargs["max_tokens"] = max_tokens
        if tools:
            kwargs["tools"] = self._convert_tools(tools)

        t0 = time.monotonic()
        response = self._client.chat.completions.create(**kwargs)
        latency = (time.monotonic() - t0) * 1000

        choice = response.choices[0]
        content = choice.message.content or ""
        tool_calls = []
        if choice.message.tool_calls:
            for tc in choice.message.tool_calls:
                tool_calls.append(ToolCall(
                    id=tc.id,
                    name=tc.function.name,
                    arguments=json.loads(tc.function.arguments),
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
            raw_message=choice.message.model_dump(exclude_none=True) if tool_calls else None,
        )
