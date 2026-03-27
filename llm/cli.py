#!/usr/bin/env python3
"""CLI bridge for LLM providers — called by the Next.js dashboard API.

Reads a JSON request from stdin, calls the provider, and writes JSON lines to stdout.
Protocol:
  - Streaming mode (default): {"chunk":"text"} per line, then {"done":true}
  - Sync mode (--sync flag): full response text on stdout

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import json
import sys

# Add project root to path
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from llm.base import LLMMessage
from llm.registry import get_provider


def main() -> None:
    sync_mode = "--sync" in sys.argv

    raw = sys.stdin.read()
    if not raw.strip():
        print(json.dumps({"error": "Empty input"}), file=sys.stderr)
        sys.exit(1)

    try:
        req = json.loads(raw)
    except json.JSONDecodeError as e:
        print(json.dumps({"error": f"Invalid JSON: {e}"}), file=sys.stderr)
        sys.exit(1)

    provider_name = req.get("provider", "claude")
    messages_raw = req.get("messages", [])
    temperature = req.get("temperature", 0.7)
    max_tokens = req.get("max_tokens", 4096)

    if not messages_raw:
        print(json.dumps({"error": "No messages provided"}), file=sys.stderr)
        sys.exit(1)

    # Convert to LLMMessage objects
    messages = [
        LLMMessage(role=m["role"], content=m["content"])
        for m in messages_raw
    ]

    try:
        provider = get_provider(provider_name)
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

    if sync_mode:
        print(response.content)
    else:
        # Stream as JSON lines (simulate streaming for non-streaming providers)
        # Split response into chunks for progressive display
        content = response.content
        chunk_size = 50
        for i in range(0, len(content), chunk_size):
            chunk = content[i : i + chunk_size]
            print(json.dumps({"chunk": chunk}), flush=True)

        # Final stats
        print(
            json.dumps(
                {
                    "done": True,
                    "stats": {
                        "provider": provider.name,
                        "model": response.model,
                        "input_tokens": response.input_tokens,
                        "output_tokens": response.output_tokens,
                        "latency_ms": response.latency_ms,
                    },
                }
            ),
            flush=True,
        )


if __name__ == "__main__":
    main()
