#!/usr/bin/env python3
"""Slowloris / resource exhaustion detector (non-destructive).

CWE-400 (Uncontrolled Resource Consumption), CWE-770 (Allocation Without Limits)

Checks:
- Connection timeout behavior (keeps partial HTTP requests open)
- Max concurrent connections accepted
- Request body timeout enforcement
- Detection only — does NOT actually denial-of-service the target

Usage:
    python slowloris_check.py --target https://example.com
    python slowloris_check.py --target https://example.com --max-conns 20

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import argparse
import json
import socket
import ssl
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

OUTPUT_DIR = Path("/output") if Path("/output").exists() else Path("reports/slowloris-check")

# Safety limits: this is detection, not exploitation
MAX_TEST_CONNECTIONS = 50
MAX_HOLD_SECONDS = 30
PARTIAL_HEADER = "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n"


def _create_socket(host: str, port: int, use_ssl: bool, timeout: int = 10) -> socket.socket | None:
    """Create a TCP (optionally TLS) socket."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.connect((host, port))
        return sock
    except Exception:
        return None


def check_slowloris_susceptibility(
    host: str, port: int, use_ssl: bool, max_conns: int = 20, hold_time: int = 15
) -> dict:
    """Test if server keeps partial connections alive (CWE-400).

    Strategy:
    1. Open N connections with partial HTTP headers (no final \\r\\n)
    2. Wait hold_time seconds, sending keep-alive headers periodically
    3. Check how many connections remain alive
    4. If >80% stay alive, server likely vulnerable to slowloris
    """
    max_conns = min(max_conns, MAX_TEST_CONNECTIONS)
    hold_time = min(hold_time, MAX_HOLD_SECONDS)
    partial = PARTIAL_HEADER.format(host=host).encode()

    sockets: list[socket.socket] = []
    opened = 0
    failed = 0

    # Phase 1: Open connections with partial headers
    for _ in range(max_conns):
        sock = _create_socket(host, port, use_ssl)
        if sock:
            try:
                sock.send(partial)
                sockets.append(sock)
                opened += 1
            except Exception:
                failed += 1
                try:
                    sock.close()
                except Exception:
                    pass
        else:
            failed += 1

    if opened == 0:
        return {
            "vulnerable": False,
            "connections_opened": 0,
            "connections_alive": 0,
            "hold_time": hold_time,
            "detail": "Could not open any connections",
        }

    # Phase 2: Keep connections alive with partial headers
    start = time.time()
    alive_at_intervals: list[int] = [opened]

    while time.time() - start < hold_time:
        time.sleep(3)
        keep_alive_header = f"X-Ping: {int(time.time())}\r\n".encode()
        alive = 0
        dead: list[int] = []
        for i, sock in enumerate(sockets):
            try:
                sock.send(keep_alive_header)
                alive += 1
            except Exception:
                dead.append(i)
        # Remove dead sockets
        for idx in reversed(dead):
            try:
                sockets[idx].close()
            except Exception:
                pass
            sockets.pop(idx)
        alive_at_intervals.append(alive)

    # Phase 3: Cleanup
    final_alive = len(sockets)
    for sock in sockets:
        try:
            sock.close()
        except Exception:
            pass

    survival_rate = final_alive / opened if opened > 0 else 0
    vulnerable = survival_rate > 0.8

    return {
        "vulnerable": vulnerable,
        "connections_opened": opened,
        "connections_failed": failed,
        "connections_alive": final_alive,
        "survival_rate": round(survival_rate, 2),
        "hold_time": hold_time,
        "alive_timeline": alive_at_intervals,
        "detail": (
            f"Server kept {final_alive}/{opened} partial connections alive over {hold_time}s "
            f"({survival_rate:.0%} survival rate)"
        ),
    }


def check_connection_limit(host: str, port: int, use_ssl: bool) -> dict:
    """Test max concurrent connections accepted (CWE-770)."""
    sockets: list[socket.socket] = []
    max_reached = 0

    for i in range(MAX_TEST_CONNECTIONS):
        sock = _create_socket(host, port, use_ssl, timeout=3)
        if sock:
            try:
                sock.send(f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n\r\n".encode())
                sockets.append(sock)
                max_reached = i + 1
            except Exception:
                try:
                    sock.close()
                except Exception:
                    pass
                break
        else:
            break

    for sock in sockets:
        try:
            sock.close()
        except Exception:
            pass

    return {
        "max_connections": max_reached,
        "limit_hit": max_reached >= MAX_TEST_CONNECTIONS,
        "detail": (
            f"Server accepted {max_reached} concurrent connections"
            + (" (limit not reached — may accept more)" if max_reached >= MAX_TEST_CONNECTIONS else "")
        ),
    }


def check_request_timeout(host: str, port: int, use_ssl: bool) -> dict:
    """Check if server enforces request completion timeout."""
    sock = _create_socket(host, port, use_ssl, timeout=35)
    if not sock:
        return {"timeout_enforced": True, "detail": "Could not connect", "timeout_seconds": 0}

    # Send partial request, wait for server to close
    partial = f"POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 1000000\r\n\r\n".encode()
    try:
        sock.send(partial)
        start = time.time()
        sock.settimeout(35)
        try:
            data = sock.recv(4096)
            elapsed = time.time() - start
            timeout_enforced = elapsed < 30
        except socket.timeout:
            elapsed = time.time() - start
            timeout_enforced = False
    except Exception:
        elapsed = 0
        timeout_enforced = True
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return {
        "timeout_enforced": timeout_enforced,
        "timeout_seconds": round(elapsed, 1),
        "detail": (
            f"Server {'enforced' if timeout_enforced else 'did NOT enforce'} request timeout "
            f"(waited {elapsed:.1f}s)"
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Slowloris/resource exhaustion detector")
    parser.add_argument("--target", "-t", required=True, help="Target URL")
    parser.add_argument("--max-conns", type=int, default=20, help="Max test connections (default: 20, max: 50)")
    parser.add_argument("--hold-time", type=int, default=15, help="Hold time in seconds (default: 15, max: 30)")
    parser.add_argument("--rate-limit", type=int, default=50)
    parser.add_argument("--config", help="Config YAML path")
    parser.add_argument("--output", "-o", default=str(OUTPUT_DIR / "results.json"))
    args = parser.parse_args()

    parsed = urlparse(args.target)
    use_ssl = parsed.scheme == "https"
    host = parsed.hostname or parsed.netloc
    port = parsed.port or (443 if use_ssl else 80)

    print(f"[*] Slowloris Detector — Target: {host}:{port} (SSL: {use_ssl})")
    print(f"[*] Non-destructive detection mode (max {args.max_conns} connections, {args.hold_time}s hold)")

    findings: list[dict] = []

    # Test 1: Slowloris susceptibility
    print("\n[*] Test 1: Slowloris susceptibility...")
    slowloris = check_slowloris_susceptibility(host, port, use_ssl, args.max_conns, args.hold_time)
    print(f"  {slowloris['detail']}")
    if slowloris["vulnerable"]:
        findings.append({
            "id": "slowloris-susceptible",
            "name": "Slowloris DoS Susceptibility",
            "severity": "high",
            "cwe": "CWE-400",
            "url": args.target,
            "detail": slowloris["detail"],
            "evidence": json.dumps(slowloris),
        })

    # Test 2: Connection limit
    print("\n[*] Test 2: Connection limit check...")
    conn_limit = check_connection_limit(host, port, use_ssl)
    print(f"  {conn_limit['detail']}")
    if conn_limit["limit_hit"]:
        findings.append({
            "id": "no-connection-limit",
            "name": "No Connection Rate Limiting Detected",
            "severity": "medium",
            "cwe": "CWE-770",
            "url": args.target,
            "detail": conn_limit["detail"],
            "evidence": json.dumps(conn_limit),
        })

    # Test 3: Request timeout
    print("\n[*] Test 3: Request timeout enforcement...")
    timeout_result = check_request_timeout(host, port, use_ssl)
    print(f"  {timeout_result['detail']}")
    if not timeout_result["timeout_enforced"]:
        findings.append({
            "id": "no-request-timeout",
            "name": "Missing Request Completion Timeout",
            "severity": "medium",
            "cwe": "CWE-400",
            "url": args.target,
            "detail": timeout_result["detail"],
            "evidence": json.dumps(timeout_result),
        })

    # Write output
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(findings, indent=2))

    print(f"\n{'='*50}")
    print(f"Total findings: {len(findings)}")
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = sum(1 for f in findings if f.get("severity") == sev)
        if count:
            print(f"  {sev.upper()}: {count}")
    print(f"Output: {args.output}")


if __name__ == "__main__":
    main()
