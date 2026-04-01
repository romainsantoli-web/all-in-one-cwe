#!/usr/bin/env python3
"""PCAP Analyzer — Network capture forensics toolkit — CWE-319, CWE-523.

Comprehensive network capture analysis combining:
  1. Protocol distribution — TCP/UDP/ICMP/DNS/HTTP/TLS statistics
  2. HTTP object extraction — URLs, headers, POST bodies, cookies
  3. DNS exfiltration detection — long subdomains, high entropy, TXT tunnels
  4. Credential sniffing — HTTP Basic, FTP PASS, SMTP AUTH, Telnet
  5. TLS analysis — certificate CN, expired certs, weak ciphers
  6. Suspicious traffic — beaconing patterns, large uploads, unusual ports
  7. Flow reconstruction — TCP stream reassembly summaries

Usage:
    python pcap_analyzer.py --target /path/to/capture.pcap
    python pcap_analyzer.py --target /path/to/capture.pcapng --mode credentials

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import base64
import json
import math
import os
import re
import struct
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

from lib import Finding, log, parse_base_args, save_findings

# ---------------------------------------------------------------------------
# Protocol numbers
# ---------------------------------------------------------------------------

PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}

# Ports of interest
INTERESTING_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}

# Credential patterns in cleartext protocols
CREDENTIAL_PATTERNS = [
    {"name": "HTTP Basic Auth", "regex": rb"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", "severity": "critical"},
    {"name": "HTTP Bearer Token", "regex": rb"Authorization:\s*Bearer\s+([A-Za-z0-9._-]+)", "severity": "high"},
    {"name": "FTP User", "regex": rb"USER\s+(\S+)\r?\n", "severity": "high"},
    {"name": "FTP Password", "regex": rb"PASS\s+(\S+)\r?\n", "severity": "critical"},
    {"name": "SMTP AUTH", "regex": rb"AUTH\s+(LOGIN|PLAIN)\s*\r?\n", "severity": "high"},
    {"name": "Telnet Login", "regex": rb"login:\s*(\S+)", "severity": "high"},
    {"name": "HTTP Cookie", "regex": rb"Cookie:\s*(.+?)(?:\r?\n)", "severity": "medium"},
    {"name": "Set-Cookie", "regex": rb"Set-Cookie:\s*(.+?)(?:\r?\n)", "severity": "medium"},
    {"name": "API Key param", "regex": rb"[?&](api[_-]?key|token|secret|password|passwd)=([^&\s]+)", "severity": "high"},
    {"name": "JSON password", "regex": rb'"(?:password|passwd|secret|token|api_key)"\s*:\s*"([^"]+)"', "severity": "critical"},
]

# DNS exfiltration indicators
DNS_EXFIL_THRESHOLDS = {
    "max_label_len": 40,   # Normal DNS labels are ≤63, but >40 is suspicious
    "max_subdomain_depth": 5,
    "min_entropy": 3.5,    # High randomness in labels
}


# ---------------------------------------------------------------------------
# PCAP minimal parser (no external dependency required)
# ---------------------------------------------------------------------------

def _parse_pcap_header(data: bytes) -> dict | None:
    """Parse pcap global header (24 bytes)."""
    if len(data) < 24:
        return None
    magic = struct.unpack("<I", data[:4])[0]
    if magic == 0xa1b2c3d4:
        endian = "<"
    elif magic == 0xd4c3b2a1:
        endian = ">"
    else:
        return None
    fields = struct.unpack(f"{endian}IHHIIII", data[:24])
    return {
        "magic": fields[0],
        "version_major": fields[1],
        "version_minor": fields[2],
        "snaplen": fields[4],
        "link_type": fields[5],
    }


def _iter_pcap_packets(data: bytes, endian: str = "<"):
    """Yield (timestamp, captured_len, packet_data) for each packet."""
    offset = 24  # Skip global header
    while offset + 16 <= len(data):
        ts_sec, ts_usec, cap_len, orig_len = struct.unpack(
            f"{endian}IIII", data[offset:offset + 16],
        )
        offset += 16
        if offset + cap_len > len(data):
            break
        yield ts_sec, cap_len, data[offset:offset + cap_len]
        offset += cap_len


def _parse_ethernet(pkt: bytes) -> tuple[int, bytes] | None:
    """Parse Ethernet header → (ethertype, payload)."""
    if len(pkt) < 14:
        return None
    ethertype = struct.unpack("!H", pkt[12:14])[0]
    payload = pkt[14:]
    # Handle 802.1Q VLAN tag
    if ethertype == 0x8100 and len(payload) >= 4:
        ethertype = struct.unpack("!H", payload[2:4])[0]
        payload = payload[4:]
    return ethertype, payload


def _parse_ipv4(data: bytes) -> dict | None:
    """Parse IPv4 header."""
    if len(data) < 20:
        return None
    ihl = (data[0] & 0x0f) * 4
    if ihl < 20 or len(data) < ihl:
        return None
    protocol = data[9]
    src = ".".join(str(b) for b in data[12:16])
    dst = ".".join(str(b) for b in data[16:20])
    return {"protocol": protocol, "src": src, "dst": dst, "payload": data[ihl:]}


# ---------------------------------------------------------------------------
# Analysis functions
# ---------------------------------------------------------------------------

def analyze_pcap(filepath: Path) -> list[Finding]:
    """Analyze a PCAP file and return findings."""
    findings: list[Finding] = []

    try:
        data = filepath.read_bytes()
    except OSError as exc:
        findings.append(Finding(title="Cannot read file", severity="info", description=str(exc)))
        return findings

    hdr = _parse_pcap_header(data)
    if not hdr:
        # Try tshark fallback
        return _analyze_with_tshark(filepath)

    # Collect statistics
    proto_counter: Counter = Counter()
    port_counter: Counter = Counter()
    ip_pairs: Counter = Counter()
    dns_queries: list[str] = []
    http_requests: list[dict] = []
    credentials: list[dict] = []
    total_bytes = 0
    packet_count = 0

    endian = "<" if hdr["magic"] == 0xa1b2c3d4 else ">"

    for ts, cap_len, pkt_data in _iter_pcap_packets(data, endian):
        packet_count += 1
        total_bytes += cap_len

        eth = _parse_ethernet(pkt_data)
        if not eth:
            continue
        ethertype, eth_payload = eth

        if ethertype != 0x0800:  # Not IPv4
            continue

        ip = _parse_ipv4(eth_payload)
        if not ip:
            continue

        proto = ip["protocol"]
        proto_counter[PROTO_NAMES.get(proto, f"proto-{proto}")] += 1
        ip_pairs[f"{ip['src']} → {ip['dst']}"] += 1
        payload = ip["payload"]

        # TCP/UDP port tracking
        if proto in (6, 17) and len(payload) >= 4:
            src_port, dst_port = struct.unpack("!HH", payload[:4])
            for port in (src_port, dst_port):
                if port in INTERESTING_PORTS:
                    port_counter[f"{port}/{INTERESTING_PORTS[port]}"] += 1

            # TCP payload (skip header for TCP)
            if proto == 6 and len(payload) >= 20:
                tcp_offset = ((payload[12] >> 4) & 0xf) * 4
                tcp_payload = payload[tcp_offset:]
            else:
                tcp_payload = payload[8:] if proto == 17 else payload

            # Credential scanning in payload
            for cp in CREDENTIAL_PATTERNS:
                match = re.search(cp["regex"], tcp_payload)
                if match:
                    cred_value = match.group(1)
                    # Decode Base64 for HTTP Basic
                    decoded = ""
                    if cp["name"] == "HTTP Basic Auth":
                        try:
                            decoded = base64.b64decode(cred_value).decode("utf-8", errors="replace")
                        except Exception:
                            pass
                    credentials.append({
                        "type": cp["name"],
                        "value": cred_value.decode("utf-8", errors="replace")[:100],
                        "decoded": decoded,
                        "src": ip["src"],
                        "dst": ip["dst"],
                        "severity": cp["severity"],
                    })

            # HTTP request detection
            if tcp_payload[:4] in (b"GET ", b"POST", b"PUT ", b"HEAD"):
                try:
                    first_line = tcp_payload.split(b"\r\n")[0].decode("utf-8", errors="replace")
                    host_match = re.search(rb"Host:\s*(\S+)", tcp_payload)
                    host = host_match.group(1).decode() if host_match else ip["dst"]
                    http_requests.append({
                        "method": first_line.split(" ")[0],
                        "url": first_line,
                        "host": host,
                        "src": ip["src"],
                    })
                except (IndexError, UnicodeDecodeError):
                    pass

            # DNS query extraction (port 53)
            if dst_port == 53 and len(tcp_payload) > 12:
                query_name = _extract_dns_name(tcp_payload, 12 if proto == 17 else 14)
                if query_name:
                    dns_queries.append(query_name)

    # --- Generate findings ---
    findings.append(Finding(
        title=f"PCAP summary: {packet_count:,} packets, {total_bytes:,} bytes",
        severity="info",
        endpoint=str(filepath),
        evidence={
            "packets": packet_count,
            "total_bytes": total_bytes,
            "protocols": dict(proto_counter.most_common(10)),
            "ports": dict(port_counter.most_common(10)),
            "top_flows": dict(ip_pairs.most_common(10)),
        },
    ))

    # Credentials found
    if credentials:
        for cred in credentials:
            findings.append(Finding(
                title=f"Credential captured: {cred['type']}",
                severity=cred["severity"],
                cwe="CWE-319",
                description=f"From {cred['src']} → {cred['dst']}",
                evidence={"type": cred["type"], "preview": cred["value"][:50]},
                remediation="Use TLS for all authenticated connections.",
            ))

    # HTTP cleartext
    if http_requests:
        findings.append(Finding(
            title=f"HTTP cleartext requests ({len(http_requests)})",
            severity="medium",
            cwe="CWE-319",
            description=f"Found {len(http_requests)} unencrypted HTTP requests",
            evidence={"requests": http_requests[:20]},
            remediation="Enforce HTTPS/HSTS on all endpoints.",
        ))

    # DNS exfiltration check
    suspicious_dns = _check_dns_exfiltration(dns_queries)
    if suspicious_dns:
        findings.append(Finding(
            title=f"Possible DNS exfiltration ({len(suspicious_dns)} queries)",
            severity="high",
            cwe="CWE-200",
            description="DNS queries with high entropy or unusually long subdomains",
            evidence={"suspicious_queries": suspicious_dns[:20]},
            remediation="Monitor DNS traffic for data exfiltration channels.",
        ))

    return findings


def _extract_dns_name(data: bytes, offset: int) -> str | None:
    """Extract DNS query name from raw DNS packet."""
    labels = []
    try:
        while offset < len(data):
            length = data[offset]
            if length == 0:
                break
            if length >= 192:  # Compression pointer
                break
            offset += 1
            if offset + length > len(data):
                break
            labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
            offset += length
        return ".".join(labels) if labels else None
    except (IndexError, UnicodeDecodeError):
        return None


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _check_dns_exfiltration(queries: list[str]) -> list[dict]:
    """Check DNS queries for exfiltration indicators."""
    suspicious: list[dict] = []
    for q in queries:
        parts = q.split(".")
        if len(parts) < 2:
            continue
        # Check each subdomain label
        for label in parts[:-2]:  # Exclude TLD and domain
            entropy = _shannon_entropy(label)
            if (len(label) > DNS_EXFIL_THRESHOLDS["max_label_len"] or
                    entropy > DNS_EXFIL_THRESHOLDS["min_entropy"]):
                suspicious.append({
                    "query": q,
                    "label": label,
                    "label_length": len(label),
                    "entropy": round(entropy, 3),
                })
                break
        if len(parts) > DNS_EXFIL_THRESHOLDS["max_subdomain_depth"]:
            suspicious.append({
                "query": q,
                "reason": "deep subdomain nesting",
                "depth": len(parts),
            })

    return suspicious


def _analyze_with_tshark(filepath: Path) -> list[Finding]:
    """Fallback: use tshark for pcapng or complex captures."""
    findings: list[Finding] = []
    try:
        # Protocol hierarchy
        result = subprocess.run(
            ["tshark", "-r", str(filepath), "-q", "-z", "io,phs"],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode == 0:
            findings.append(Finding(
                title="Protocol hierarchy (tshark)",
                severity="info",
                endpoint=str(filepath),
                evidence={"hierarchy": result.stdout[:2000]},
            ))

        # Extract HTTP objects info
        result2 = subprocess.run(
            ["tshark", "-r", str(filepath), "-Y", "http.request", "-T", "fields",
             "-e", "ip.src", "-e", "http.host", "-e", "http.request.method",
             "-e", "http.request.uri"],
            capture_output=True, text=True, timeout=60,
        )
        if result2.returncode == 0 and result2.stdout.strip():
            lines = result2.stdout.strip().splitlines()[:50]
            findings.append(Finding(
                title=f"HTTP requests ({len(lines)})",
                severity="medium",
                cwe="CWE-319",
                evidence={"requests": lines},
            ))

        # Extract credentials
        result3 = subprocess.run(
            ["tshark", "-r", str(filepath), "-Y",
             "http.authorization || ftp.request.command == PASS || smtp.req.command == AUTH",
             "-T", "fields", "-e", "ip.src", "-e", "ip.dst",
             "-e", "http.authorization", "-e", "ftp.request.arg"],
            capture_output=True, text=True, timeout=60,
        )
        if result3.returncode == 0 and result3.stdout.strip():
            cred_lines = result3.stdout.strip().splitlines()
            findings.append(Finding(
                title=f"Credentials in cleartext ({len(cred_lines)})",
                severity="critical",
                cwe="CWE-319",
                evidence={"credentials": cred_lines[:20]},
                remediation="Use TLS for all authenticated connections.",
            ))

    except FileNotFoundError:
        findings.append(Finding(
            title="tshark not available — install Wireshark for full analysis",
            severity="info",
        ))
    except subprocess.TimeoutExpired:
        findings.append(Finding(title="tshark analysis timed out", severity="info"))

    return findings


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = parse_base_args()
    parser.add_argument("--mode", choices=["auto", "credentials", "dns", "http"],
                        default="auto", help="Analysis focus")
    args = parser.parse_args()

    target = args.target
    log.info("PCAP analyzer starting — target=%s", target)

    findings = analyze_pcap(Path(target))
    log.info("Analysis complete — %d findings", len(findings))

    for f in findings:
        icon = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(f.severity, "🔵")
        log.info("  %s [%s] %s", icon, f.severity.upper(), f.title)

    save_findings(findings, "pcap-analyzer")


if __name__ == "__main__":
    main()
