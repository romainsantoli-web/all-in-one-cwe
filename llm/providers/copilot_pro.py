"""GitHub Copilot Pro provider — full catalog via OAuth device flow + JWT.

Authentication flow:
  1. OAuth device flow with client_id = Iv1.b507a08c87ecfe98 (VS Code)
  2. Exchange OAuth token for Copilot JWT via /copilot_internal/v2/token
  3. Use JWT as Bearer token on api.githubcopilot.com/chat/completions

The JWT expires every ~30 min — auto-refresh via cached OAuth token.
Uses httpx directly — no openai/anthropic SDK needed.

Available models (as of March 2026):
  Claude: claude-haiku-4.5, claude-sonnet-4, claude-sonnet-4.5, claude-sonnet-4.6,
          claude-opus-4.5, claude-opus-4.6
  GPT:    gpt-4.1, gpt-4o, gpt-5-mini, gpt-5.1, gpt-5.2, gpt-5.3, gpt-5.4
  Codex:  gpt-5.1-codex, gpt-5.1-codex-mini, gpt-5.1-codex-max, gpt-5.2-codex,
          gpt-5.3-codex
  Gemini: gemini-2.5-pro, gemini-3-pro, gemini-3.1-pro
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
import uuid as _uuid
from typing import Any

from llm.base import (
    LLMMessage,
    LLMProvider,
    LLMResponse,
    ToolCall,
    ToolDefinition,
)

logger = logging.getLogger(__name__)


class CopilotProProvider(LLMProvider):
    """GitHub Copilot Pro provider — full catalog (Claude, GPT-5, Gemini, Grok)."""

    name = "copilot-pro"

    _CLIENT_ID = "Iv1.b507a08c87ecfe98"
    _BASE_URL = "https://api.githubcopilot.com"

    def __init__(self, model: str | None = None, api_key: str | None = None, **kwargs: Any):
        self._oauth_token: str | None = kwargs.pop("oauth_token", None)
        self._jwt_expires: int = 0
        jwt = api_key or os.environ.get("COPILOT_JWT")

        if not jwt and not self._oauth_token:
            jwt, self._oauth_token, self._jwt_expires = self._load_cached_tokens()

        if not jwt and self._oauth_token:
            jwt = self._refresh_jwt()

        if not jwt:
            raise ValueError(
                "CopilotProProvider requires a Copilot JWT or OAuth token. "
                "Run the device flow first or set COPILOT_JWT env var."
            )

        super().__init__(model=model, api_key=jwt, **kwargs)
        self._jwt = jwt

    def _default_model(self) -> str:
        return "claude-sonnet-4.6"

    # ── Token management ────────────────────────────────────────────────────

    @staticmethod
    def _load_cached_tokens() -> tuple[str | None, str | None, int]:
        """Load cached tokens from /tmp/copilot_token.json."""
        try:
            with open("/tmp/copilot_token.json") as f:
                data = json.load(f)
            jwt = data.get("copilot_jwt")
            oauth = data.get("oauth_token")
            exp = int(data.get("expires_at", 0))
            if jwt and exp > int(time.time()) + 60:
                return jwt, oauth, exp
            return None, oauth, 0
        except (FileNotFoundError, json.JSONDecodeError, KeyError):
            return None, None, 0

    def _refresh_jwt(self) -> str | None:
        """Refresh Copilot JWT using cached OAuth token."""
        import httpx as _httpx

        if not self._oauth_token:
            return None
        try:
            r = _httpx.get(
                "https://api.github.com/copilot_internal/v2/token",
                headers={
                    "Authorization": f"token {self._oauth_token}",
                    "Accept": "application/json",
                    "Editor-Version": "vscode/1.96.0",
                    "Editor-Plugin-Version": "copilot-chat/0.24.0",
                },
                timeout=10,
            )
            if r.status_code == 200:
                data = r.json()
                jwt = data.get("token")
                self._jwt_expires = int(data.get("expires_at", 0))
                with open("/tmp/copilot_token.json", "w") as f:
                    json.dump({
                        "oauth_token": self._oauth_token,
                        "copilot_jwt": jwt,
                        "expires_at": self._jwt_expires,
                    }, f)
                return jwt
        except Exception:
            pass
        return None

    def _ensure_valid_jwt(self):
        """Auto-refresh JWT if about to expire."""
        if self._jwt_expires and int(time.time()) > self._jwt_expires - 60:
            new_jwt = self._refresh_jwt()
            if new_jwt:
                self._jwt = new_jwt

    # ── API routing ─────────────────────────────────────────────────────────

    _RESPONSES_MODELS = (
        "gpt-5.4", "gpt-5.3-codex", "gpt-5.2-codex",
        "gpt-5.1-codex", "gpt-5.1-codex-mini", "gpt-5.1-codex-max",
    )

    _COMPLETION_TOKENS_MODELS = (
        "o1", "o1-mini", "o1-preview", "o3", "o3-mini", "o3-pro",
        "o4-mini", "gpt-5", "gpt-5-mini", "gpt-5-nano",
    )

    def _is_responses_model(self) -> bool:
        return any(self.model.startswith(p) for p in self._RESPONSES_MODELS)

    def _copilot_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._jwt}",
            "Content-Type": "application/json",
            "Editor-Version": "vscode/1.96.0",
            "Editor-Plugin-Version": "copilot-chat/0.24.0",
            "Copilot-Integration-Id": "vscode-chat",
            "Openai-Intent": "conversation-panel",
        }

    # ── Message/tool conversion ─────────────────────────────────────────────

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

    def _convert_messages_to_responses_input(self, messages: list[LLMMessage]) -> list[dict]:
        """Convert to OpenAI Responses API input items."""
        items: list[dict] = []
        for msg in messages:
            if msg.role == "system":
                items.append({"type": "message", "role": "developer", "content": msg.content})
            elif msg.role == "user":
                items.append({"type": "message", "role": "user", "content": msg.content})
            elif msg.role == "assistant":
                if msg.content:
                    items.append({"type": "message", "role": "assistant", "content": msg.content})
                for tc in msg.tool_calls:
                    items.append({
                        "type": "function_call",
                        "name": tc.name,
                        "arguments": json.dumps(tc.arguments) if isinstance(tc.arguments, dict) else tc.arguments,
                        "call_id": tc.id,
                    })
            elif msg.role == "tool":
                items.append({
                    "type": "function_call_output",
                    "call_id": msg.tool_call_id,
                    "output": msg.content,
                })
        return items

    def _convert_tools_for_responses(self, tools: list[ToolDefinition]) -> list[dict]:
        return [
            {
                "type": "function",
                "name": t.name,
                "description": t.description,
                "parameters": t.parameters,
            }
            for t in tools
        ]

    # ── Chat dispatch ───────────────────────────────────────────────────────

    def chat(
        self,
        messages: list[LLMMessage],
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        self._ensure_valid_jwt()
        if self._is_responses_model():
            return self._chat_responses(messages, tools, temperature, max_tokens)
        return self._chat_completions(messages, tools, temperature, max_tokens)

    # ── /responses API (Codex models) ───────────────────────────────────────

    def _chat_responses(
        self,
        messages: list[LLMMessage],
        tools: list[ToolDefinition] | None,
        temperature: float,
        max_tokens: int,
    ) -> LLMResponse:
        import httpx as _httpx

        payload: dict[str, Any] = {
            "model": self.model,
            "input": self._convert_messages_to_responses_input(messages),
            "max_output_tokens": max_tokens,
        }
        if tools:
            payload["tools"] = self._convert_tools_for_responses(tools)

        t0 = time.monotonic()
        r = _httpx.post(
            f"{self._BASE_URL}/responses",
            headers=self._copilot_headers(),
            json=payload,
            timeout=120,
        )
        latency = (time.monotonic() - t0) * 1000

        if r.status_code != 200:
            raise RuntimeError(f"Codex /responses error ({r.status_code}): {r.text[:300]}")

        data = r.json()
        content = ""
        tool_calls: list[ToolCall] = []
        finish_reason = "stop"

        for item in data.get("output", []):
            if item.get("type") == "message":
                for c in item.get("content", []):
                    content += c.get("text", "")
            elif item.get("type") == "function_call":
                args_str = item.get("arguments", "{}")
                try:
                    args = json.loads(args_str) if isinstance(args_str, str) else args_str
                except json.JSONDecodeError:
                    args = {"raw": args_str}
                tool_calls.append(ToolCall(
                    id=item.get("call_id", f"codex_{item.get('id', 'unknown')}"),
                    name=item["name"],
                    arguments=args,
                ))
                finish_reason = "tool_calls"

        usage = data.get("usage", {})
        in_tokens = usage.get("input_tokens", 0)
        out_tokens = usage.get("output_tokens", 0)
        self._total_requests += 1
        self._total_input_tokens += in_tokens
        self._total_output_tokens += out_tokens

        raw_msg = None
        if tool_calls:
            raw_msg = {
                "role": "assistant",
                "content": content or None,
                "tool_calls": [
                    {"id": tc.id, "type": "function", "function": {"name": tc.name, "arguments": json.dumps(tc.arguments)}}
                    for tc in tool_calls
                ],
            }

        return LLMResponse(
            content=content,
            tool_calls=tool_calls,
            finish_reason=finish_reason,
            input_tokens=in_tokens,
            output_tokens=out_tokens,
            model=self.model,
            latency_ms=latency,
            raw_message=raw_msg,
        )

    # ── /chat/completions API (Claude, GPT, Gemini, Grok) ──────────────────

    def _chat_completions(
        self,
        messages: list[LLMMessage],
        tools: list[ToolDefinition] | None,
        temperature: float,
        max_tokens: int,
    ) -> LLMResponse:
        import httpx as _httpx

        use_completion_tokens = any(
            self.model.startswith(p) for p in self._COMPLETION_TOKENS_MODELS
        )
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": self._convert_messages(messages),
        }
        if use_completion_tokens:
            payload["max_completion_tokens"] = max_tokens
        else:
            payload["temperature"] = temperature
            payload["max_tokens"] = max_tokens
        if tools:
            payload["tools"] = self._convert_tools(tools)

        t0 = time.monotonic()
        r = _httpx.post(
            f"{self._BASE_URL}/chat/completions",
            headers=self._copilot_headers(),
            json=payload,
            timeout=120,
        )
        latency = (time.monotonic() - t0) * 1000

        if r.status_code != 200:
            raise RuntimeError(f"CopilotPro error ({r.status_code}): {r.text[:500]}")

        data = r.json()
        content = ""
        tool_calls: list[ToolCall] = []
        finish_reason = "stop"

        for choice in data.get("choices", []):
            msg = choice.get("message", {})
            if msg.get("content"):
                content = msg["content"]
            for tc in msg.get("tool_calls", []):
                func = tc.get("function", {})
                args_str = func.get("arguments", "{}")
                try:
                    args = json.loads(args_str) if isinstance(args_str, str) else args_str
                except json.JSONDecodeError:
                    args = {"raw": args_str}
                tool_calls.append(ToolCall(
                    id=tc.get("id", ""),
                    name=func.get("name", ""),
                    arguments=args,
                ))
            if choice.get("finish_reason"):
                finish_reason = choice["finish_reason"]

        usage = data.get("usage", {})
        in_tokens = usage.get("prompt_tokens", 0)
        out_tokens = usage.get("completion_tokens", 0)
        self._total_requests += 1
        self._total_input_tokens += in_tokens
        self._total_output_tokens += out_tokens

        # XML tool call fallback for Claude models on Copilot Pro
        if not tool_calls and content and tools:
            parsed = self._parse_xml_tool_calls(content)
            if parsed:
                logger.warning(
                    "CopilotPro XML fallback: parsed %d tool calls from %d chars",
                    len(parsed), len(content),
                )
                tool_calls = [parsed[0]]
                finish_reason = "tool_use"
                content = re.split(
                    r"<(?:function_calls|invoke|anythingllm)", content, maxsplit=1
                )[0].strip()

        raw_msg = None
        if tool_calls:
            raw_msg = {
                "role": "assistant",
                "content": content or None,
                "tool_calls": [
                    {"id": tc.id, "type": "function", "function": {"name": tc.name, "arguments": json.dumps(tc.arguments)}}
                    for tc in tool_calls
                ],
            }

        return LLMResponse(
            content=content,
            tool_calls=tool_calls,
            finish_reason=finish_reason,
            input_tokens=in_tokens,
            output_tokens=out_tokens,
            model=self.model,
            latency_ms=latency,
            raw_message=raw_msg,
        )

    # ── XML fallback parser ─────────────────────────────────────────────────

    @staticmethod
    def _parse_xml_tool_calls(text: str) -> list[ToolCall]:
        """Parse XML-formatted tool calls hallucinated by Claude models."""
        tool_calls: list[ToolCall] = []

        invoke_pattern = re.compile(
            r'<invoke\s+name="([^"]+)">(.*?)</invoke>', re.DOTALL,
        )
        param_pattern = re.compile(
            r'<parameter\s+name="([^"]+)">(.*?)</parameter>', re.DOTALL,
        )

        for match in invoke_pattern.finditer(text):
            func_name = match.group(1)
            body = match.group(2)

            arguments: dict[str, Any] = {}
            for param in param_pattern.finditer(body):
                key = param.group(1)
                val = param.group(2).strip()
                try:
                    arguments[key] = json.loads(val)
                except (json.JSONDecodeError, ValueError):
                    arguments[key] = val

            tool_calls.append(ToolCall(
                id=f"xml_{_uuid.uuid4().hex[:8]}",
                name=func_name,
                arguments=arguments,
            ))

        return tool_calls
