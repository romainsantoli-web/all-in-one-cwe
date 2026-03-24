"""Memory OS client — connects to Memory-os-ai via library or HTTP.

Supports two modes:
  - Library mode: direct import of memory_os_ai (fastest, same process)
  - HTTP mode: connects to MCP SSE server on port 8765 (for Docker/remote)
"""

from __future__ import annotations

import json
import logging
import os
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)

# Lazy import for library mode
_memory_lib = None


def _ensure_memory_lib():
    """Try to import memory_os_ai library."""
    global _memory_lib
    if _memory_lib is None:
        try:
            import memory_os_ai

            _memory_lib = memory_os_ai
        except ImportError:
            _memory_lib = False  # Mark as unavailable
    return _memory_lib if _memory_lib is not False else None


class MemoryClient:
    """Unified client for Memory OS AI — library or HTTP fallback."""

    def __init__(
        self,
        mode: str = "auto",
        base_url: str | None = None,
        workspace: str | None = None,
    ):
        """Initialize Memory OS client.

        Args:
            mode: "library", "http", or "auto" (try library first)
            base_url: HTTP endpoint (default: http://127.0.0.1:8765)
            workspace: Workspace path for memory isolation
        """
        self._base_url = (
            base_url or os.environ.get("MEMORY_URL", "http://127.0.0.1:8765")
        ).rstrip("/")
        self._workspace = workspace or os.getcwd()
        self._memory = None
        self._mode = "none"

        if mode in ("auto", "library"):
            lib = _ensure_memory_lib()
            if lib:
                try:
                    self._memory = lib.HebbianMemory()
                    self._mode = "library"
                    logger.info("Memory OS: library mode (direct import)")
                    return
                except Exception as e:
                    logger.warning("Memory OS library init failed: %s", e)

        if mode in ("auto", "http"):
            if self._ping_http():
                self._mode = "http"
                logger.info("Memory OS: HTTP mode (%s)", self._base_url)
                return

        if mode not in ("auto",):
            raise ConnectionError(f"Memory OS not available in {mode} mode")
        logger.warning("Memory OS: not available (install memory-os-ai or start SSE server)")

    @property
    def available(self) -> bool:
        return self._mode != "none"

    @property
    def mode(self) -> str:
        return self._mode

    def _ping_http(self) -> bool:
        """Check if the HTTP server is reachable."""
        try:
            req = urllib.request.Request(
                f"{self._base_url}/health",
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                return resp.status == 200
        except Exception:
            return False

    def _mcp_call(self, tool_name: str, arguments: dict) -> Any:
        """Call an MCP tool via JSON-RPC over HTTP."""
        payload = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        }).encode()

        req = urllib.request.Request(
            f"{self._base_url}/mcp",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())

        if "error" in data:
            raise RuntimeError(f"MCP error: {data['error']}")
        return data.get("result")

    # ── Core operations ─────────────────────────────────────────────────────

    def store(self, key: str, data: dict, metadata: dict | None = None) -> bool:
        """Store a memory record."""
        if self._mode == "library":
            self._memory.store(key, data, metadata)
            return True
        elif self._mode == "http":
            self._mcp_call("memory_store", {
                "key": key,
                "data": json.dumps(data),
                "metadata": json.dumps(metadata or {}),
            })
            return True
        return False

    def search(self, query: str, limit: int = 10) -> list[dict]:
        """Semantic search across memories."""
        if self._mode == "library":
            results = self._memory.search(query, limit=limit)
            return [
                {"key": r.key, "weight": r.weight, "data": r.data, "layer": getattr(r, "layer", "L2")}
                for r in results
            ]
        elif self._mode == "http":
            result = self._mcp_call("memory_search", {"query": query, "limit": limit})
            return result if isinstance(result, list) else []
        return []

    def get(self, key: str) -> dict | None:
        """Retrieve a single memory by key."""
        if self._mode == "library":
            r = self._memory.get(key)
            return {"key": r.key, "weight": r.weight, "data": r.data} if r else None
        elif self._mode == "http":
            return self._mcp_call("memory_store", {"key": key})
        return None

    def status(self) -> dict:
        """Get memory system status."""
        if self._mode == "library":
            return {
                "mode": "library",
                "available": True,
                "total_memories": len(self._memory.search("", limit=10000)),
            }
        elif self._mode == "http":
            return self._mcp_call("memory_status", {}) or {"mode": "http", "available": True}
        return {"mode": "none", "available": False}
