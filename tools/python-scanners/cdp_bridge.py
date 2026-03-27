#!/usr/bin/env python3
"""CDP Bridge — Generic Chrome DevTools Protocol client for security scanners.

Provides high-level functions for browser automation via CDP WebSocket:
- cdp_connect()  → establish connection to Chrome debug port
- cdp_send()     → send CDP command and get response
- cdp_fetch()    → intercept and modify network requests via Fetch domain
- cdp_eval()     → evaluate JavaScript in page context

Requires: Chrome/Chromium running with --remote-debugging-port=9222
Launch: chromium --headless --remote-debugging-port=9222 --no-sandbox

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(__file__))
from lib import log

# ---------------------------------------------------------------------------
# CDP Connection
# ---------------------------------------------------------------------------

CDP_URL = os.environ.get("CDP_URL", "http://localhost:9222")


@dataclass
class CDPSession:
    """Persistent CDP WebSocket session."""

    ws: Any = None  # websocket.WebSocket
    _msg_id: int = 0
    _callbacks: dict[int, Any] = field(default_factory=dict)
    _events: list[dict] = field(default_factory=list)
    _listener_thread: threading.Thread | None = None
    _running: bool = False

    def next_id(self) -> int:
        self._msg_id += 1
        return self._msg_id


def cdp_connect(url: str | None = None, target_url: str | None = None) -> CDPSession:
    """Connect to a Chrome instance via CDP.

    Args:
        url: Chrome debug URL (default: CDP_URL env var or localhost:9222)
        target_url: If set, navigate to this URL after connecting

    Returns:
        CDPSession with active WebSocket connection
    """
    try:
        import websocket
        import requests as req_lib
    except ImportError as e:
        log.error("CDP bridge requires: pip install websocket-client requests — %s", e)
        raise

    base = url or CDP_URL
    # Get available targets
    resp = req_lib.get(f"{base}/json/version", timeout=5)
    resp.raise_for_status()
    version_info = resp.json()
    ws_url = version_info.get("webSocketDebuggerUrl", "")

    if not ws_url:
        # Try to get first page target
        targets = req_lib.get(f"{base}/json", timeout=5).json()
        page_targets = [t for t in targets if t.get("type") == "page"]
        if not page_targets:
            # Create a new target
            new_target = req_lib.put(f"{base}/json/new", timeout=5).json()
            ws_url = new_target.get("webSocketDebuggerUrl", "")
        else:
            ws_url = page_targets[0].get("webSocketDebuggerUrl", "")

    if not ws_url:
        raise ConnectionError("No WebSocket URL found in Chrome debug endpoint")

    session = CDPSession()
    session.ws = websocket.create_connection(ws_url, timeout=10)
    log.info("CDP connected: %s", ws_url)

    # Navigate if target URL specified
    if target_url:
        cdp_send(session, "Page.navigate", {"url": target_url})
        time.sleep(2)  # Wait for page load

    return session


def cdp_send(session: CDPSession, method: str, params: dict | None = None) -> dict:
    """Send a CDP command and wait for response.

    Args:
        session: Active CDP session
        method: CDP method (e.g. "Runtime.evaluate")
        params: Method parameters

    Returns:
        CDP response dict
    """
    msg_id = session.next_id()
    msg = {"id": msg_id, "method": method, "params": params or {}}
    session.ws.send(json.dumps(msg))

    # Wait for response with matching ID
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            raw = session.ws.recv()
            if not raw:
                continue
            data = json.loads(raw)
            if data.get("id") == msg_id:
                if "error" in data:
                    log.warning("CDP error: %s", data["error"])
                return data
            # Store events for later processing
            if "method" in data:
                session._events.append(data)
        except Exception:
            break

    return {"error": {"message": "CDP response timeout"}}


def cdp_eval(session: CDPSession, expression: str) -> Any:
    """Evaluate JavaScript in the page context.

    Args:
        session: Active CDP session
        expression: JavaScript expression to evaluate

    Returns:
        Evaluation result value
    """
    resp = cdp_send(session, "Runtime.evaluate", {
        "expression": expression,
        "returnByValue": True,
        "awaitPromise": True,
    })
    result = resp.get("result", {}).get("result", {})
    if result.get("type") == "undefined":
        return None
    return result.get("value")


def cdp_fetch_enable(
    session: CDPSession,
    patterns: list[dict] | None = None,
) -> None:
    """Enable Fetch domain for network interception.

    Args:
        session: Active CDP session
        patterns: List of URL patterns to intercept, e.g.
                  [{"urlPattern": "*api*", "requestStage": "Request"}]
    """
    params: dict[str, Any] = {}
    if patterns:
        params["patterns"] = patterns
    else:
        params["patterns"] = [{"urlPattern": "*", "requestStage": "Response"}]
    cdp_send(session, "Fetch.enable", params)


def cdp_get_response_body(session: CDPSession, request_id: str) -> tuple[str, bool]:
    """Get the response body for an intercepted request.

    Returns:
        Tuple of (body_text, is_base64_encoded)
    """
    resp = cdp_send(session, "Fetch.getResponseBody", {"requestId": request_id})
    result = resp.get("result", {})
    return result.get("body", ""), result.get("base64Encoded", False)


def cdp_continue_request(session: CDPSession, request_id: str) -> None:
    """Continue an intercepted request without modification."""
    cdp_send(session, "Fetch.continueRequest", {"requestId": request_id})


def cdp_continue_response(session: CDPSession, request_id: str) -> None:
    """Continue an intercepted response without modification."""
    cdp_send(session, "Fetch.continueResponse", {"requestId": request_id})


def cdp_collect_events(
    session: CDPSession,
    event_name: str | None = None,
    duration_s: float = 5.0,
) -> list[dict]:
    """Collect CDP events for a given duration.

    Args:
        session: Active CDP session
        event_name: Filter by event method name (e.g. "Fetch.requestPaused")
        duration_s: How long to collect events (seconds)

    Returns:
        List of matching event dicts
    """
    events: list[dict] = []
    deadline = time.monotonic() + duration_s

    while time.monotonic() < deadline:
        try:
            session.ws.settimeout(0.5)
            raw = session.ws.recv()
            if not raw:
                continue
            data = json.loads(raw)
            if "method" in data:
                if event_name is None or data["method"] == event_name:
                    events.append(data)
        except Exception:
            continue

    return events


def cdp_close(session: CDPSession) -> None:
    """Close the CDP WebSocket connection."""
    try:
        if session.ws:
            session.ws.close()
    except Exception:
        pass
