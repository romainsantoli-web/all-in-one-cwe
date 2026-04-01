#!/usr/bin/env python3
"""CLI bridge for LLM providers — called by the Next.js dashboard API.

Reads a JSON request from stdin, calls the provider, and writes JSON lines to stdout.
Protocol:
  - Streaming mode (default): {"chunk":"text"} per line, then {"done":true}
  - Sync mode (--sync flag): full response text on stdout
  - Agent mode (--agent flag): agentic loop with tool calling

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time

# Add project root to path
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from llm.base import LLMMessage, ToolCall
from llm.registry import get_provider

# Maximum agentic loop iterations (safety limit)
MAX_AGENT_STEPS = 30


def _emit(data: dict) -> None:
    """Emit a JSON line to stdout (SSE protocol)."""
    print(json.dumps(data, default=str), flush=True)


def _convert_message(m: dict) -> LLMMessage:
    """Convert a raw dict to LLMMessage, preserving tool_calls and tool_call_id."""
    tool_calls = []
    for tc in m.get("tool_calls", []):
        tool_calls.append(ToolCall(
            id=tc.get("id", ""),
            name=tc.get("name", ""),
            arguments=tc.get("arguments", {}),
        ))
    return LLMMessage(
        role=m["role"],
        content=m.get("content", ""),
        tool_calls=tool_calls,
        tool_call_id=m.get("tool_call_id"),
        name=m.get("name"),
    )


def run_chat(req: dict) -> None:
    """Standard chat mode — single LLM call, stream chunks."""
    provider_name = req.get("provider", "claude")
    model_name = req.get("model")
    messages_raw = req.get("messages", [])
    temperature = req.get("temperature", 0.7)
    max_tokens = req.get("max_tokens", 4096)

    if not messages_raw:
        print(json.dumps({"error": "No messages provided"}), file=sys.stderr)
        sys.exit(1)

    messages = [_convert_message(m) for m in messages_raw]

    kwargs: dict = {}
    if model_name:
        kwargs["model"] = model_name
    try:
        provider = get_provider(provider_name, **kwargs)
    except KeyError as e:
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        sys.exit(1)

    try:
        response = provider.chat(
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )
    except Exception as e:
        print(json.dumps({"error": f"LLM call failed: {e}"}), file=sys.stderr)
        sys.exit(1)

    content = response.content
    chunk_size = 50
    for i in range(0, len(content), chunk_size):
        chunk = content[i : i + chunk_size]
        _emit({"chunk": chunk})

    _emit({
        "done": True,
        "stats": {
            "provider": provider.name,
            "model": response.model,
            "input_tokens": response.input_tokens,
            "output_tokens": response.output_tokens,
            "latency_ms": response.latency_ms,
        },
    })


def run_agent(req: dict) -> None:
    """Agentic mode — loop with tool calling until LLM stops or max steps reached."""
    from llm.agent_tools import AGENT_TOOLS, execute_tool

    # Thread conversation_id to agent_tools via env variable
    conv_id = req.get("conversation_id", "")
    if conv_id and isinstance(conv_id, str):
        if re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", conv_id):
            os.environ["CONVERSATION_ID"] = conv_id

    provider_name = req.get("provider", "claude")
    model_name = req.get("model")
    messages_raw = req.get("messages", [])
    temperature = req.get("temperature", 0.4)  # lower for agentic
    max_tokens = req.get("max_tokens", 4096)
    max_steps = min(req.get("max_steps", MAX_AGENT_STEPS), MAX_AGENT_STEPS)

    if not messages_raw:
        print(json.dumps({"error": "No messages provided"}), file=sys.stderr)
        sys.exit(1)

    messages = [_convert_message(m) for m in messages_raw]

    kwargs: dict = {}
    if model_name:
        kwargs["model"] = model_name
    try:
        provider = get_provider(provider_name, **kwargs)
    except KeyError as e:
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        sys.exit(1)

    total_input = 0
    total_output = 0

    for step in range(max_steps):
        _emit({"event": "thinking", "step": step + 1, "max_steps": max_steps})

        try:
            response = provider.chat(
                messages=messages,
                tools=AGENT_TOOLS,
                temperature=temperature,
                max_tokens=max_tokens,
            )
        except Exception as e:
            _emit({"event": "error", "message": f"LLM call failed: {e}"})
            break

        total_input += response.input_tokens
        total_output += response.output_tokens

        # If the LLM responded with text (no tool calls), stream it and finish
        if not response.has_tool_calls:
            content = response.content
            chunk_size = 50
            for i in range(0, len(content), chunk_size):
                _emit({"chunk": content[i : i + chunk_size]})
            break

        # LLM wants to call tools — process each tool call
        # First, add assistant message with tool calls to history
        assistant_msg = LLMMessage(
            role="assistant",
            content=response.content or "",
            tool_calls=response.tool_calls,
            _raw=response.raw_message,
        )
        messages.append(assistant_msg)

        for tc in response.tool_calls:
            _emit({
                "event": "tool_call",
                "step": step + 1,
                "tool": tc.name,
                "arguments": tc.arguments,
            })

            start = time.time()
            result = execute_tool(tc.name, tc.arguments)
            elapsed = round((time.time() - start) * 1000)

            _emit({
                "event": "tool_result",
                "step": step + 1,
                "tool": tc.name,
                "result": result[:4000],  # truncate for display
                "elapsed_ms": elapsed,
            })

            # Add tool result to conversation
            messages.append(LLMMessage(
                role="tool",
                content=result,
                tool_call_id=tc.id,
                name=tc.name,
            ))
    else:
        # Loop exhausted — ask LLM for a final summary
        _emit({"event": "max_steps_reached", "steps": max_steps})
        messages.append(LLMMessage(
            role="user",
            content="You have reached the maximum number of steps. Please provide a final summary of what you found and accomplished.",
        ))
        try:
            response = provider.chat(
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
            )
            content = response.content
            chunk_size = 50
            for i in range(0, len(content), chunk_size):
                _emit({"chunk": content[i : i + chunk_size]})
            total_input += response.input_tokens
            total_output += response.output_tokens
        except Exception:
            pass

    _emit({
        "done": True,
        "stats": {
            "provider": provider_name,
            "model": model_name or "default",
            "input_tokens": total_input,
            "output_tokens": total_output,
        },
    })


def main() -> None:
    sync_mode = "--sync" in sys.argv
    agent_mode = "--agent" in sys.argv

    raw = sys.stdin.read()
    if not raw.strip():
        print(json.dumps({"error": "Empty input"}), file=sys.stderr)
        sys.exit(1)

    try:
        req = json.loads(raw)
    except json.JSONDecodeError as e:
        print(json.dumps({"error": f"Invalid JSON: {e}"}), file=sys.stderr)
        sys.exit(1)

    if agent_mode:
        run_agent(req)
    elif sync_mode:
        # Sync mode — return full text on stdout
        provider_name = req.get("provider", "claude")
        model_name = req.get("model")
        messages_raw = req.get("messages", [])

        messages = [_convert_message(m) for m in messages_raw]
        kwargs: dict = {}
        if model_name:
            kwargs["model"] = model_name
        provider = get_provider(provider_name, **kwargs)
        response = provider.chat(
            messages=messages,
            temperature=req.get("temperature", 0.7),
            max_tokens=req.get("max_tokens", 4096),
        )
        print(response.content)
    else:
        run_chat(req)


if __name__ == "__main__":
    main()
