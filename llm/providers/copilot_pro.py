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


# Headers mimicking VS Code Copilot extension — must match exactly
# (same as Compta's working implementation)
COPILOT_HEADERS = {
    "Editor-Version": "vscode/1.95.0",
    "Editor-Plugin-Version": "copilot-chat/0.23.2",
    "User-Agent": "GitHubCopilotChat/0.23.2",
}


class CopilotProProvider(LLMProvider):
    """GitHub Copilot Pro provider — full catalog (Claude, GPT-5, Gemini, Grok)."""

    name = "copilot-pro"

    _CLIENT_ID = "Iv1.b507a08c87ecfe98"
    _BASE_URL = "https://api.githubcopilot.com"
    _SESSION_TOKEN_URL = "https://api.github.com/copilot_internal/v2/token"
    _TOKEN_FILE = "/tmp/copilot_token.json"

    def __init__(self, model: str | None = None, api_key: str | None = None, **kwargs: Any):
        self._oauth_token: str | None = kwargs.pop("oauth_token", None)

        # Priority: explicit oauth_token kwarg > COPILOT_OAUTH_TOKEN env > COPILOT_JWT env > cached file
        if not self._oauth_token:
            self._oauth_token = os.environ.get("COPILOT_OAUTH_TOKEN")

        raw_key = api_key or os.environ.get("COPILOT_JWT")
        # If the value looks like a GitHub PAT/OAuth token, treat it as OAuth token
        if raw_key and raw_key.startswith(("ghp_", "gho_", "github_pat_", "ghu_")):
            logger.info("COPILOT_JWT looks like a PAT/OAuth token — will use for session exchange")
            self._oauth_token = self._oauth_token or raw_key
            raw_key = None

        if not self._oauth_token:
            _, self._oauth_token, _ = self._load_cached_tokens()

        # With an OAuth token, get a fresh session token (like Compta does)
        if self._oauth_token:
            jwt = self._get_session_token(self._oauth_token)
            if not jwt:
                raise ValueError(
                    "Copilot session token exchange failed. "
                    "Your OAuth token may be invalid. Re-authenticate via device flow."
                )
        elif raw_key:
            # Treat as a direct session JWT (rare — usually from manual override)
            jwt = raw_key
        else:
            raise ValueError(
                "CopilotProProvider requires authentication. "
                "Use the OAuth device flow on the /llm page or set COPILOT_OAUTH_TOKEN."
            )

        super().__init__(model=model, api_key=jwt, **kwargs)
        self._jwt = jwt

    # ── OAuth Device Flow ───────────────────────────────────────────────────

    @classmethod
    def start_device_flow(cls) -> dict[str, str]:
        """Start GitHub OAuth device flow. Returns user_code, verification_uri, device_code."""
        import httpx as _httpx

        r = _httpx.post(
            "https://github.com/login/device/code",
            headers={"Accept": "application/json", **COPILOT_HEADERS},
            data={"client_id": cls._CLIENT_ID, "scope": "copilot"},
            timeout=15,
        )
        r.raise_for_status()
        data = r.json()
        return {
            "user_code": data["user_code"],
            "verification_uri": data["verification_uri"],
            "device_code": data["device_code"],
            "expires_in": data.get("expires_in", 900),
            "interval": data.get("interval", 5),
        }

    @classmethod
    def poll_device_flow(cls, device_code: str) -> dict[str, Any]:
        """Poll for OAuth token. Returns {status, oauth_token?, error?}."""
        import httpx as _httpx

        r = _httpx.post(
            "https://github.com/login/oauth/access_token",
            headers={"Accept": "application/json", **COPILOT_HEADERS},
            data={
                "client_id": cls._CLIENT_ID,
                "device_code": device_code,
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            },
            timeout=15,
        )
        r.raise_for_status()
        data = r.json()

        if "access_token" in data:
            oauth_token = data["access_token"]
            # Verify token works by getting a session token
            session = cls._get_session_token(oauth_token)
            if session:
                # Persist OAuth token (long-lived) — session tokens are fetched fresh per call
                with open(cls._TOKEN_FILE, "w") as f:
                    json.dump({"oauth_token": oauth_token}, f)
                return {"status": "ok", "oauth_token": oauth_token}
            return {"status": "error", "error": "Got OAuth token but session exchange failed"}

        error = data.get("error", "unknown")
        if error == "authorization_pending":
            return {"status": "pending"}
        if error == "slow_down":
            return {"status": "slow_down"}
        if error == "expired_token":
            return {"status": "expired"}
        return {"status": "error", "error": data.get("error_description", error)}

    @classmethod
    def _get_session_token(cls, oauth_token: str) -> str | None:
        """Exchange GitHub OAuth token for a Copilot session token.

        This is called fresh on every API call — same pattern as Compta.
        The session token expires every ~30 min.
        """
        import httpx as _httpx

        headers = {
            "Authorization": f"token {oauth_token}",
            "Accept": "application/json",
            **COPILOT_HEADERS,
        }
        try:
            r = _httpx.get(
                cls._SESSION_TOKEN_URL,
                headers=headers,
                timeout=15,
            )
            if r.status_code == 200:
                data = r.json()
                return data.get("token")
            logger.warning(
                "Copilot session token exchange failed: %d %s",
                r.status_code, r.text[:200],
            )
        except Exception as e:
            logger.error("Session token exchange error: %s", e)
        return None

    @classmethod
    def get_auth_status(cls) -> dict[str, Any]:
        """Check current auth status: try to get a session token from stored OAuth token."""
        # Check env first
        oauth = os.environ.get("COPILOT_OAUTH_TOKEN")
        if not oauth:
            _, oauth, _ = cls._load_cached_tokens()
        if not oauth:
            return {"authenticated": False, "has_oauth": False}
        # Verify OAuth token still works
        session = cls._get_session_token(oauth)
        if session:
            return {"authenticated": True, "has_oauth": True}
        return {"authenticated": False, "has_oauth": True, "expired": True}

    def _default_model(self) -> str:
        return "claude-sonnet-4.6"

    # ── Token management ────────────────────────────────────────────────────

    @classmethod
    def _load_cached_tokens(cls) -> tuple[str | None, str | None, int]:
        """Load cached OAuth token from /tmp/copilot_token.json."""
        try:
            with open(cls._TOKEN_FILE) as f:
                data = json.load(f)
            oauth = data.get("oauth_token")
            return None, oauth, 0
        except (FileNotFoundError, json.JSONDecodeError, KeyError):
            return None, None, 0

    def _refresh_session(self) -> str | None:
        """Get a fresh session token using the stored OAuth token."""
        if not self._oauth_token:
            return None
        return self._get_session_token(self._oauth_token)

    def _ensure_valid_jwt(self):
        """Get a fresh session token before every call (like Compta)."""
        if self._oauth_token:
            new_jwt = self._refresh_session()
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
        """Build headers for Copilot API calls — matches Compta's get_copilot_api_headers()."""
        return {
            "Authorization": f"Bearer {self._jwt}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Copilot-Integration-Id": "vscode-chat",
            "Openai-Intent": "conversation-panel",
            **COPILOT_HEADERS,
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
