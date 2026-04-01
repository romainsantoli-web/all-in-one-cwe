"""Agent tool definitions and executors for the LLM agentic loop.

Provides security scanning tools, shell execution, file I/O, CDP browser control,
per-conversation workspace, and report generation that the LLM can call via
native function calling.

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import URLError

from llm.base import ToolDefinition

PROJECT_ROOT = Path(os.environ.get("PROJECT_ROOT", Path(__file__).resolve().parent.parent))

# Recovery engine (self-contained v4 copy)
RECOVERY_ENGINE_ROOT = PROJECT_ROOT / "tools" / "recovery-engine"
RECOVERY_CLI = RECOVERY_ENGINE_ROOT / "packages" / "cli" / "dist" / "index.js"
RECOVERY_TIMEOUT = 600  # 10 min max for crack operations

# Max output to return from any tool (prevent context blow-up)
MAX_OUTPUT = 8000
# Max shell command execution time
SHELL_TIMEOUT = 120
# Max file size to read
MAX_FILE_SIZE = 50_000

# Per-conversation workspace root
WORKSPACE_ROOT = PROJECT_ROOT / "reports" / "llm-workspaces"

# CDP config
CDP_URL = os.environ.get("CDP_URL", "http://localhost:9222")

# --- Blocked patterns for shell commands (safety) ---
_BLOCKED_SHELL_PATTERNS = [
    "rm -rf /",
    "mkfs.",
    "dd if=",
    ":(){:|:&};:",
    "> /dev/sd",
    "chmod -R 777 /",
    "curl|bash",
    "wget|bash",
    "shutdown",
    "reboot",
    "init 0",
    "kill -9 1",
]


# ---------------------------------------------------------------------------
# Tool definitions (OpenAI function-calling format)
# ---------------------------------------------------------------------------

AGENT_TOOLS: list[ToolDefinition] = [
    ToolDefinition(
        name="run_scan",
        description=(
            "Run a security scanner tool against a target URL. "
            "Available tools include: nuclei, sqlmap, nikto, ffuf, nmap, testssl, "
            "xss-scanner, ssrf-scanner, idor-scanner, auth-bypass, secret-leak, "
            "api-discovery, cache-deception, websocket-scanner, waf-bypass, "
            "source-map-scanner, hidden-endpoint-scanner, and 60+ more. "
            "Returns the scan output (findings JSON or raw output)."
        ),
        parameters={
            "type": "object",
            "properties": {
                "tool": {
                    "type": "string",
                    "description": "Name of the scanner tool to run (e.g. 'nuclei', 'xss-scanner')",
                },
                "target": {
                    "type": "string",
                    "description": "Target URL (must be http:// or https://)",
                },
                "options": {
                    "type": "object",
                    "description": "Optional extra arguments as key-value pairs (tool-specific)",
                    "additionalProperties": {"type": "string"},
                },
            },
            "required": ["tool", "target"],
        },
    ),
    ToolDefinition(
        name="shell_exec",
        description=(
            "Execute a shell command and return stdout+stderr. "
            "Use for: running custom scripts, curl requests, file manipulation, "
            "checking installed tools, writing PoC exploits, etc. "
            "Commands run in the project root directory. Timeout: 120s."
        ),
        parameters={
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Shell command to execute (e.g. 'curl -v https://target.com')",
                },
                "cwd": {
                    "type": "string",
                    "description": "Working directory (relative to project root). Default: project root.",
                },
            },
            "required": ["command"],
        },
    ),
    ToolDefinition(
        name="read_file",
        description=(
            "Read the contents of a file. "
            "Use for: reading scan reports, config files, source code, previous results. "
            "Paths are relative to the project root."
        ),
        parameters={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "File path relative to project root (e.g. 'reports/nuclei/scan-latest.json')",
                },
                "tail": {
                    "type": "integer",
                    "description": "If set, only return the last N lines of the file.",
                },
            },
            "required": ["path"],
        },
    ),
    ToolDefinition(
        name="write_file",
        description=(
            "Write content to a file. "
            "Use for: writing PoC scripts, exploit code, custom scan configs, reports. "
            "Paths are relative to the project root. Parent dirs are created automatically."
        ),
        parameters={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "File path relative to project root (e.g. 'reports/poc_xss.py')",
                },
                "content": {
                    "type": "string",
                    "description": "File content to write.",
                },
            },
            "required": ["path", "content"],
        },
    ),
    ToolDefinition(
        name="list_findings",
        description=(
            "List all findings from previous scans. "
            "Reads scan-latest.json from each tool's report directory. "
            "Returns a summary of all findings with severity, title, and tool."
        ),
        parameters={
            "type": "object",
            "properties": {
                "tool": {
                    "type": "string",
                    "description": "Filter findings to a specific tool (optional).",
                },
                "severity": {
                    "type": "string",
                    "description": "Filter by severity: critical, high, medium, low, info (optional).",
                    "enum": ["critical", "high", "medium", "low", "info"],
                },
            },
        },
    ),
    ToolDefinition(
        name="generate_report",
        description=(
            "Generate a professional security report from current findings and AUTO-SAVE it to disk. "
            "The report is saved to reports/generated-reports/ AND to the conversation workspace. "
            "Supports formats: markdown, yeswehack, hackerone, bugcrowd, intigriti, immunefi. "
            "Returns the formatted report content AND the saved file paths."
        ),
        parameters={
            "type": "object",
            "properties": {
                "format": {
                    "type": "string",
                    "description": "Report format/platform",
                    "enum": ["markdown", "yeswehack", "hackerone", "bugcrowd", "intigriti", "immunefi"],
                },
                "target": {
                    "type": "string",
                    "description": "Target URL for the report header.",
                },
                "title": {
                    "type": "string",
                    "description": "Report title (optional).",
                },
            },
            "required": ["format"],
        },
    ),
    ToolDefinition(
        name="list_tools",
        description=(
            "List all available security scanning tools with their profiles. "
            "Use this to discover what tools are available before running scans."
        ),
        parameters={
            "type": "object",
            "properties": {
                "profile": {
                    "type": "string",
                    "description": "Filter by profile (e.g. 'python-scanners', 'recon', 'fuzz').",
                },
            },
        },
    ),
    ToolDefinition(
        name="update_plan",
        description=(
            "Create or update the current task plan. ALWAYS call this tool FIRST to plan your work, "
            "then call it again to update task status as you progress. "
            "Each task has an id, title, and status (pending/in-progress/done/failed). "
            "Return the FULL list of tasks on every call (both existing and new)."
        ),
        parameters={
            "type": "object",
            "properties": {
                "tasks": {
                    "type": "array",
                    "description": "Full list of tasks with status updates.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "integer", "description": "Task number (1-based)"},
                            "title": {"type": "string", "description": "Short task description"},
                            "status": {
                                "type": "string",
                                "enum": ["pending", "in-progress", "done", "failed"],
                                "description": "Current status of this task",
                            },
                            "result": {
                                "type": "string",
                                "description": "Brief result or finding when done (optional).",
                            },
                        },
                        "required": ["id", "title", "status"],
                    },
                },
                "summary": {
                    "type": "string",
                    "description": "Brief summary of what was accomplished (set when all tasks are done).",
                },
            },
            "required": ["tasks"],
        },
    ),
    # --- VS Code-style tools ---
    ToolDefinition(
        name="list_dir",
        description=(
            "List files and subdirectories in a directory. "
            "Returns names with '/' suffix for directories. "
            "Use to explore project structure, find config files, discover scan reports."
        ),
        parameters={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Directory path relative to project root (default: '.')",
                },
                "depth": {
                    "type": "integer",
                    "description": "Max recursion depth (1=immediate children, 2=grandchildren). Default: 1, max: 3.",
                },
            },
        },
    ),
    ToolDefinition(
        name="grep_search",
        description=(
            "Search for text or regex patterns across files in the project. "
            "Like ripgrep/grep — finds exact matches or regex patterns in file contents. "
            "Returns matching lines with file path and line number. "
            "Use for: finding functions, locating config values, hunting for secrets patterns."
        ),
        parameters={
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Search pattern (plain text or regex)",
                },
                "path": {
                    "type": "string",
                    "description": "Directory or file to search in (relative to project root). Default: '.'",
                },
                "is_regex": {
                    "type": "boolean",
                    "description": "Treat pattern as regex (default: false = literal text search)",
                },
                "include": {
                    "type": "string",
                    "description": "Glob pattern to filter files (e.g. '*.py', '*.ts'). Optional.",
                },
            },
            "required": ["pattern"],
        },
    ),
    ToolDefinition(
        name="file_search",
        description=(
            "Search for files by name or glob pattern in the project tree. "
            "Returns matching file paths. "
            "Use to find specific files, config files, reports, scripts."
        ),
        parameters={
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Glob pattern or filename to search for (e.g. '*.json', 'Dockerfile', '**/*.py')",
                },
                "path": {
                    "type": "string",
                    "description": "Directory to search in (relative to project root). Default: '.'",
                },
            },
            "required": ["pattern"],
        },
    ),
    ToolDefinition(
        name="fetch_webpage",
        description=(
            "Fetch the content of a web page and return its text. "
            "Useful for reading documentation, checking target responses, "
            "downloading configs, or verifying fixes. "
            "Returns the first 8000 chars of the response body."
        ),
        parameters={
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL to fetch (must be http:// or https://)",
                },
                "method": {
                    "type": "string",
                    "description": "HTTP method (GET, POST, HEAD). Default: GET.",
                    "enum": ["GET", "POST", "HEAD"],
                },
                "headers": {
                    "type": "object",
                    "description": "Optional HTTP headers as key-value pairs.",
                    "additionalProperties": {"type": "string"},
                },
            },
            "required": ["url"],
        },
    ),
    # --- CDP Browser tools ---
    ToolDefinition(
        name="cdp_exec",
        description=(
            "Execute a Chrome DevTools Protocol command on a running Chrome instance. "
            "Use for: evaluating JavaScript in a live page, extracting cookies/tokens, "
            "intercepting network requests, capturing screenshots, DOM manipulation. "
            "Requires Chrome running with --remote-debugging-port (check CDP status first). "
            "Common methods: Runtime.evaluate, Network.getAllCookies, Page.navigate, "
            "Page.captureScreenshot, DOM.getDocument."
        ),
        parameters={
            "type": "object",
            "properties": {
                "method": {
                    "type": "string",
                    "description": "CDP method (e.g. 'Runtime.evaluate', 'Page.navigate', 'Network.getAllCookies')",
                },
                "params": {
                    "type": "object",
                    "description": "CDP method parameters. For Runtime.evaluate, use {expression: 'JS code', returnByValue: true}.",
                    "additionalProperties": True,
                },
            },
            "required": ["method"],
        },
    ),
    ToolDefinition(
        name="browse_page",
        description=(
            "Navigate to a URL in the CDP browser and return the rendered page content. "
            "Unlike fetch_webpage, this executes JavaScript and returns the final DOM. "
            "Use for: testing XSS payloads, checking client-side rendering, "
            "extracting dynamic content, verifying CSP behavior, single-page apps. "
            "Returns: page title, full text content, and any console errors."
        ),
        parameters={
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL to navigate to (must be http:// or https://)",
                },
                "wait_ms": {
                    "type": "integer",
                    "description": "Milliseconds to wait after page load for JS execution (default: 3000, max: 15000)",
                },
                "extract_selector": {
                    "type": "string",
                    "description": "CSS selector to extract specific elements (optional). Returns matching elements' text.",
                },
            },
            "required": ["url"],
        },
    ),
    # --- Per-conversation workspace tools ---
    ToolDefinition(
        name="workspace_write",
        description=(
            "Write a file to the current conversation's dedicated workspace folder. "
            "Each conversation gets its own isolated directory for PoC scripts, notes, "
            "exploit code, analysis files, and reports. "
            "Use this instead of write_file when you want organized per-conversation output. "
            "Parent directories inside the workspace are created automatically."
        ),
        parameters={
            "type": "object",
            "properties": {
                "conversation_id": {
                    "type": "string",
                    "description": "Conversation ID (provided in system context). Used to isolate files per conversation.",
                },
                "filename": {
                    "type": "string",
                    "description": "Filename within the workspace (e.g. 'poc_xss.py', 'notes.md', 'exploit/payload.sh')",
                },
                "content": {
                    "type": "string",
                    "description": "File content to write.",
                },
            },
            "required": ["conversation_id", "filename", "content"],
        },
    ),
    ToolDefinition(
        name="workspace_read",
        description=(
            "Read a file from the current conversation's workspace folder. "
            "Use to review PoC scripts, analysis notes, or any file you previously wrote "
            "with workspace_write."
        ),
        parameters={
            "type": "object",
            "properties": {
                "conversation_id": {
                    "type": "string",
                    "description": "Conversation ID.",
                },
                "filename": {
                    "type": "string",
                    "description": "Filename within the workspace to read.",
                },
            },
            "required": ["conversation_id", "filename"],
        },
    ),
    ToolDefinition(
        name="workspace_list",
        description=(
            "List all files in the current conversation's workspace folder. "
            "Use to see what PoC scripts, analysis files, and notes have been created."
        ),
        parameters={
            "type": "object",
            "properties": {
                "conversation_id": {
                    "type": "string",
                    "description": "Conversation ID.",
                },
            },
            "required": ["conversation_id"],
        },
    ),
    # --- Password Recovery tools ---
    ToolDefinition(
        name="vault_scan",
        description=(
            "Scan this machine for ALL encrypted files across 23 supported formats organized in 7 categories:\n"
            "\n"
            "WALLET (crypto):\n"
            "  - MetaMask vault (.json) — PBKDF2 + AES-256-GCM\n"
            "  - Bitcoin Core wallet (.dat) — SHA-512 KDF + AES-256-CBC\n"
            "  - Ethereum Keystore (.json) — scrypt/PBKDF2 + AES-128-CTR\n"
            "  - Electrum Wallet (.json, .dat) — PBKDF2-SHA512 + AES-256-CBC\n"
            "  - Exodus seed.seco (.seco) — scrypt + AES-256-GCM\n"
            "  - Multi-coin: Phantom, Trust Wallet, LTC, DOGE, DASH, Monero, Solana, Cardano (.dat, .keys, .json, .seco, .sqlite)\n"
            "\n"
            "PASSWORD-MANAGER:\n"
            "  - KeePass (.kdbx) — AES-KDF / Argon2\n"
            "  - 1Password (.opvault, .agilekeychain) — PBKDF2 + AES\n"
            "  - Bitwarden (.json) — PBKDF2/Argon2 + AES-256\n"
            "  - LastPass (.csv, .html, .dat) — PBKDF2-SHA256 + AES-256\n"
            "\n"
            "ARCHIVE:\n"
            "  - ZIP (.zip) — ZipCrypto / WinZip AES\n"
            "  - RAR (.rar) — RAR3/RAR5 AES + PBKDF2\n"
            "  - 7-Zip (.7z) — AES-256 + SHA-256 KDF\n"
            "\n"
            "DOCUMENT:\n"
            "  - PDF (.pdf) — RC4 / AES-128 / AES-256\n"
            "  - Microsoft Office (.docx, .xlsx, .pptx, .doc, .xls, .ppt) — PBKDF2 + AES\n"
            "\n"
            "DISK:\n"
            "  - VeraCrypt/TrueCrypt (.hc, .tc, .vol) — PBKDF2 + AES-XTS\n"
            "  - macOS DMG (.dmg) — PBKDF2 + AES\n"
            "  - LUKS (.img, .luks, .raw) — PBKDF2/Argon2 + AES\n"
            "  - FileVault 2 (.sparsebundle, .dmg, .img) — PBKDF2-SHA256 + AES-XTS\n"
            "  - BitLocker (.bek, .img, .vhd, .vhdx) — SHA-256 + AES-CCM\n"
            "\n"
            "NETWORK:\n"
            "  - WiFi WPA/WPA2 (.pcap, .pcapng, .hccapx, .cap) — PBKDF2-SHA1\n"
            "  - SSH Private Key (.pem, .key, .id_rsa, .id_ed25519, .id_ecdsa, .id_dsa) — bcrypt/EVP + AES\n"
            "\n"
            "MOBILE:\n"
            "  - iPhone Backup (.plist, .mdbackup) — PBKDF2 + AES\n"
            "\n"
            "Returns a JSON list of found encrypted files with type, path, and encryption details. "
            "Use deep=true for forensic mode (Time Machine, iCloud, external drives, Spotlight, Trash)."
        ),
        parameters={
            "type": "object",
            "properties": {
                "scan_path": {
                    "type": "string",
                    "description": "Directory to scan (default: user home). Must be under $HOME or /tmp.",
                },
                "deep": {
                    "type": "boolean",
                    "description": "Enable deep forensic scan (Time Machine, iCloud, external drives, old profiles, Spotlight, Trash). Default: false.",
                },
                "category": {
                    "type": "string",
                    "description": "Filter by category: wallet, password-manager, archive, document, disk, network, mobile. Default: all.",
                    "enum": ["wallet", "password-manager", "archive", "document", "disk", "network", "mobile"],
                },
                "format": {
                    "type": "string",
                    "description": (
                        "Filter by specific format ID: metamask, bitcoin-core, ethereum-keystore, electrum, "
                        "exodus, multicoin, keepass, 1password, bitwarden, lastpass, zip, rar, 7zip, pdf, "
                        "office, veracrypt, dmg, luks, filevault, bitlocker, wifi, ssh, iphone-backup"
                    ),
                },
            },
        },
    ),
    ToolDefinition(
        name="vault_extract",
        description=(
            "Extract encrypted vault/file data. Two modes:\n"
            "\n"
            "MODE 1 — Browser extraction (extract_all=false):\n"
            "  Reads MetaMask/Phantom LevelDB/IndexedDB from browser local storage.\n"
            "  Extracts the encrypted vault JSON containing the seed phrase.\n"
            "  Browsers: Chrome, Firefox, Brave, Edge.\n"
            "\n"
            "MODE 2 — Extract-all (extract_all=true):\n"
            "  Finds and copies ALL encrypted files from the system to a working directory.\n"
            "  Covers all 23 formats: .json (MetaMask/Ethereum/Bitwarden), .dat (Bitcoin Core/Electrum/LastPass),\n"
            "  .seco (Exodus), .keys/.sqlite (multi-coin), .kdbx (KeePass), .opvault/.agilekeychain (1Password),\n"
            "  .zip, .rar, .7z, .pdf, .docx/.xlsx/.pptx, .hc/.tc/.vol (VeraCrypt), .dmg (macOS),\n"
            "  .img/.luks/.raw (LUKS), .sparsebundle (FileVault), .bek/.vhd/.vhdx (BitLocker),\n"
            "  .pcap/.pcapng/.hccapx (WiFi), .pem/.key/.id_rsa/.id_ed25519 (SSH),\n"
            "  .plist/.mdbackup (iPhone).\n"
            "\n"
            "  Can filter by category or format to extract only specific file types."
        ),
        parameters={
            "type": "object",
            "properties": {
                "browser": {
                    "type": "string",
                    "description": "Browser to extract from (mode 1 only): chrome, firefox, brave, edge. Default: chrome.",
                    "enum": ["chrome", "firefox", "brave", "edge"],
                },
                "output_path": {
                    "type": "string",
                    "description": "Path to save extracted files (relative to project root). Default: reports/extracted/",
                },
                "extract_all": {
                    "type": "boolean",
                    "description": "If true, find and extract ALL encrypted files from system (mode 2). Default: false.",
                },
                "category": {
                    "type": "string",
                    "description": "Filter extract-all by category: wallet, password-manager, archive, document, disk, network, mobile.",
                    "enum": ["wallet", "password-manager", "archive", "document", "disk", "network", "mobile"],
                },
                "format": {
                    "type": "string",
                    "description": (
                        "Filter extract-all by format ID: metamask, bitcoin-core, ethereum-keystore, electrum, "
                        "exodus, multicoin, keepass, 1password, bitwarden, lastpass, zip, rar, 7zip, pdf, "
                        "office, veracrypt, dmg, luks, filevault, bitlocker, wifi, ssh, iphone-backup"
                    ),
                },
            },
        },
    ),
    ToolDefinition(
        name="password_recover",
        description=(
            "Launch password recovery against ANY encrypted file. Auto-detects format among 23 types:\n"
            "\n"
            "WALLETS: MetaMask (.json vault), Bitcoin Core (wallet.dat), Ethereum Keystore (.json),\n"
            "  Electrum (.json/.dat), Exodus (seed.seco), Phantom/Trust/LTC/DOGE/DASH/Monero/Solana/Cardano (.dat/.keys/.json/.seco/.sqlite)\n"
            "PASSWORD MANAGERS: KeePass (.kdbx), 1Password (.opvault/.agilekeychain), Bitwarden (.json), LastPass (.csv/.html/.dat)\n"
            "ARCHIVES: ZIP (.zip), RAR (.rar), 7-Zip (.7z)\n"
            "DOCUMENTS: PDF (.pdf), Office (.docx/.xlsx/.pptx/.doc/.xls/.ppt)\n"
            "DISK: VeraCrypt (.hc/.tc/.vol), DMG (.dmg), LUKS (.img/.luks/.raw), FileVault (.sparsebundle), BitLocker (.bek/.vhd/.vhdx)\n"
            "NETWORK: WiFi WPA/WPA2 (.pcap/.pcapng/.hccapx/.cap), SSH keys (.pem/.key/.id_rsa/.id_ed25519/.id_ecdsa/.id_dsa)\n"
            "MOBILE: iPhone Backup (.plist/.mdbackup)\n"
            "\n"
            "Uses vectorized PBKDF2 cracking engine with multi-threaded workers. "
            "Strategies: profile (personal info), dictionary (wordlist), bruteforce, all. "
            "Returns progress updates and found password if successful."
        ),
        parameters={
            "type": "object",
            "properties": {
                "target_file": {
                    "type": "string",
                    "description": "Path to the encrypted file or vault.json to crack.",
                },
                "strategy": {
                    "type": "string",
                    "description": "Recovery strategy: profile, dictionary, bruteforce, all. Default: all.",
                    "enum": ["profile", "dictionary", "bruteforce", "all"],
                },
                "profile": {
                    "type": "object",
                    "description": "Personal info for profile-based recovery. Keys: names, dates, words, partials, oldPasswords.",
                    "properties": {
                        "names": {"type": "array", "items": {"type": "string"}, "description": "Names, nicknames, pet names"},
                        "dates": {"type": "array", "items": {"type": "string"}, "description": "Important dates (YYYY, MMDD, etc)"},
                        "words": {"type": "array", "items": {"type": "string"}, "description": "Favorite words, places, brands"},
                        "partials": {"type": "array", "items": {"type": "string"}, "description": "Partial password fragments"},
                        "oldPasswords": {"type": "array", "items": {"type": "string"}, "description": "Previously used passwords"},
                    },
                },
                "wordlist": {
                    "type": "string",
                    "description": "Path to a wordlist file for dictionary attack.",
                },
                "charset": {
                    "type": "string",
                    "description": "Character set for brute-force: lowercase, alpha, alphanumeric, full. Default: alphanumeric.",
                    "enum": ["lowercase", "alpha", "alphanumeric", "full"],
                },
                "min_length": {
                    "type": "integer",
                    "description": "Minimum password length for brute-force. Default: 4.",
                },
                "max_length": {
                    "type": "integer",
                    "description": "Maximum password length for brute-force. Default: 12.",
                },
                "threads": {
                    "type": "integer",
                    "description": "Number of worker threads. Default: CPU count.",
                },
                "format": {
                    "type": "string",
                    "description": (
                        "Force format detection (skip auto-detect). Format ID: metamask, bitcoin-core, "
                        "ethereum-keystore, electrum, exodus, multicoin, keepass, 1password, bitwarden, "
                        "lastpass, zip, rar, 7zip, pdf, office, veracrypt, dmg, luks, filevault, "
                        "bitlocker, wifi, ssh, iphone-backup"
                    ),
                },
            },
            "required": ["target_file"],
        },
    ),
    ToolDefinition(
        name="password_decrypt",
        description=(
            "Decrypt an encrypted file with a known password. Works with all 23 formats:\n"
            "  - MetaMask/Ethereum vault → reveals seed phrase / mnemonic / private keys\n"
            "  - Bitcoin Core wallet.dat → dumps wallet keys & addresses\n"
            "  - Electrum/Exodus → reveals seed phrase\n"
            "  - KeePass .kdbx → exports full password database\n"
            "  - 1Password .opvault → exports stored credentials\n"
            "  - Bitwarden/LastPass → exports vault entries\n"
            "  - ZIP/RAR/7z → extracts archive contents\n"
            "  - PDF/Office → removes protection, outputs readable file\n"
            "  - VeraCrypt/LUKS/FileVault/BitLocker → mounts volume\n"
            "  - SSH key → decrypts private key\n"
            "  - iPhone backup → decrypts backup files\n"
            "Returns the decrypted content or extraction result."
        ),
        parameters={
            "type": "object",
            "properties": {
                "vault_file": {
                    "type": "string",
                    "description": "Path to the encrypted vault/file (relative to project root).",
                },
                "password": {
                    "type": "string",
                    "description": "The password to use for decryption.",
                },
            },
            "required": ["vault_file", "password"],
        },
    ),
    ToolDefinition(
        name="list_recovery_formats",
        description=(
            "List all 23 encrypted file formats supported by the recovery engine. "
            "Shows format ID, name, file extensions, encryption type, and KDF details. "
            "Formats: metamask, bitcoin-core, ethereum-keystore, electrum, exodus, multicoin, "
            "keepass, 1password, bitwarden, lastpass, zip, rar, 7zip, pdf, office, veracrypt, "
            "dmg, luks, filevault, bitlocker, wifi, ssh, iphone-backup. "
            "Use this to understand what types of files can be recovered, and which format ID to "
            "pass to vault_scan or vault_extract for filtering."
        ),
        parameters={
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "description": "Filter output by category: wallet, password-manager, archive, document, disk, network, mobile.",
                    "enum": ["wallet", "password-manager", "archive", "document", "disk", "network", "mobile"],
                },
            },
        },
    ),
    # ------ Android ADB Bridge tools ------
    ToolDefinition(
        name="android_adb",
        description=(
            "Android ADB bridge — manage device connections for remote WiFi capture and file extraction.\n"
            "Actions:\n"
            "  - devices: List connected Android devices (USB + wireless)\n"
            "  - connect: Connect to a device over WiFi (ip:port)\n"
            "  - pair: Pair with a device using wireless debugging code (ip:port + pairing code)\n"
            "  - status: Check ADB server status + device details (model, Android version, root)\n"
            "  - forward: Forward local port to device port (e.g. for CDP on device Chrome)\n"
            "\n"
            "Prerequisites: ADB must be installed (brew install android-platform-tools).\n"
            "Device must have USB debugging or Wireless debugging enabled in Developer Options.\n"
            "For WiFi capture: device should be rooted with tcpdump available."
        ),
        parameters={
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "description": "Action to perform: devices, connect, pair, status, forward",
                    "enum": ["devices", "connect", "pair", "status", "forward"],
                },
                "target": {
                    "type": "string",
                    "description": "IP:port for connect/pair, or device serial for status. E.g. '192.168.1.100:5555'",
                },
                "pairing_code": {
                    "type": "string",
                    "description": "6-digit pairing code for wireless debugging (pair action only).",
                },
                "local_port": {
                    "type": "integer",
                    "description": "Local port for port forwarding (forward action).",
                },
                "remote_port": {
                    "type": "integer",
                    "description": "Remote device port for port forwarding (forward action).",
                },
                "serial": {
                    "type": "string",
                    "description": "Device serial to target (if multiple devices connected).",
                },
            },
            "required": ["action"],
        },
    ),
    ToolDefinition(
        name="android_wifi_capture",
        description=(
            "Capture WiFi WPA/WPA2/WPS handshake via a connected Android device.\n"
            "The phone must be rooted with tcpdump or airodump-ng installed.\n"
            "\n"
            "Workflow:\n"
            "  1. Scans available WiFi networks on the device\n"
            "  2. Sets the WiFi interface to monitor mode (requires root)\n"
            "  3. Captures WPA 4-way handshake or WPS exchange\n"
            "  4. Saves capture as .pcap/.hccapx on device\n"
            "  5. Auto-pulls capture file to local machine\n"
            "\n"
            "Actions:\n"
            "  - scan: List visible WiFi networks (SSID, BSSID, channel, signal, security)\n"
            "  - capture: Start handshake capture on target BSSID/channel\n"
            "  - deauth: Send deauth frames to force client reconnection (speeds up capture)\n"
            "  - status: Check current capture status\n"
            "  - stop: Stop active capture and pull .pcap file\n"
            "\n"
            "Output: .pcap/.pcapng/.hccapx files ready for password_recover(format='wifi')"
        ),
        parameters={
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "description": "Action: scan, capture, deauth, status, stop",
                    "enum": ["scan", "capture", "deauth", "status", "stop"],
                },
                "bssid": {
                    "type": "string",
                    "description": "Target access point BSSID (MAC address) for capture/deauth. E.g. 'AA:BB:CC:DD:EE:FF'",
                },
                "channel": {
                    "type": "integer",
                    "description": "WiFi channel to listen on (1-14 for 2.4GHz, 36-165 for 5GHz).",
                },
                "interface": {
                    "type": "string",
                    "description": "WiFi interface on the Android device. Default: wlan0",
                },
                "duration": {
                    "type": "integer",
                    "description": "Capture duration in seconds (default: 60, max: 600).",
                },
                "output_file": {
                    "type": "string",
                    "description": "Local output filename for the capture (saved to reports/captures/). Default: auto-generated.",
                },
                "serial": {
                    "type": "string",
                    "description": "Device serial if multiple connected.",
                },
            },
            "required": ["action"],
        },
    ),
    ToolDefinition(
        name="android_file_transfer",
        description=(
            "Transfer files between local machine and connected Android device via ADB.\n"
            "Actions:\n"
            "  - pull: Copy file FROM device TO local machine (e.g. capture files, wallets, DBs)\n"
            "  - push: Copy file FROM local TO device (e.g. wordlists, scripts)\n"
            "  - ls: List files in a directory on the device\n"
            "\n"
            "Common paths on Android:\n"
            "  /sdcard/ — User storage (accessible without root)\n"
            "  /sdcard/Download/ — Downloads folder\n"
            "  /data/data/<package>/ — App private data (requires root)\n"
            "  /data/misc/wifi/ — WiFi configs (requires root)\n"
            "  /tmp/ or /data/local/tmp/ — Temp directory\n"
            "\n"
            "Useful for pulling: .pcap captures, wallet files (.dat, .json, .kdbx),\n"
            "browser databases, WiFi configs (wpa_supplicant.conf)"
        ),
        parameters={
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "description": "Action: pull, push, ls",
                    "enum": ["pull", "push", "ls"],
                },
                "device_path": {
                    "type": "string",
                    "description": "Path on the Android device. Required for all actions.",
                },
                "local_path": {
                    "type": "string",
                    "description": "Local destination (pull) or source (push) path. Relative to project root. Default: reports/android/",
                },
                "serial": {
                    "type": "string",
                    "description": "Device serial if multiple connected.",
                },
            },
            "required": ["action", "device_path"],
        },
    ),
    ToolDefinition(
        name="android_shell",
        description=(
            "Execute a shell command on a connected Android device via 'adb shell'.\n"
            "Useful for:\n"
            "  - Checking root access: 'su -c id' or 'whoami'\n"
            "  - Installing capture tools: 'su -c apt install tcpdump' (Termux/Magisk)\n"
            "  - Listing WiFi networks: 'su -c iwlist wlan0 scan'\n"
            "  - Checking interfaces: 'ip link show' or 'ifconfig'\n"
            "  - Reading WiFi passwords: 'su -c cat /data/misc/wifi/WifiConfigStore.xml'\n"
            "  - Dumping saved WiFi configs: 'su -c cat /data/misc/wifi/wpa_supplicant.conf'\n"
            "  - Package management: 'pm list packages | grep -i wallet'\n"
            "  - Process listing: 'ps -A | grep -i capture'\n"
            "\n"
            "Commands are executed with a 30s timeout. Destructive commands are blocked.\n"
            "For capture operations, prefer android_wifi_capture which handles the full flow."
        ),
        parameters={
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Shell command to execute on the device.",
                },
                "serial": {
                    "type": "string",
                    "description": "Device serial if multiple connected.",
                },
                "as_root": {
                    "type": "boolean",
                    "description": "Wrap command in 'su -c' for root execution. Default: false.",
                },
            },
            "required": ["command"],
        },
    ),
    # -----------------------------------------------------------------------
    # CTF / Forensics / Reversing tools
    # -----------------------------------------------------------------------
    ToolDefinition(
        name="crypto_analyze",
        description=(
            "Cryptography analysis toolkit for CTF challenges.\n"
            "Capabilities:\n"
            "  - Identify hash types (MD5, SHA, bcrypt, NTLM, JWT, 50+ formats)\n"
            "  - Decode encoding chains (Base64, Base32, Hex, URL, ROT13, multi-layer)\n"
            "  - Frequency analysis (IC, Shannon entropy, chi-squared vs English)\n"
            "  - Caesar cipher bruteforce (all 25 shifts, scored)\n"
            "  - XOR single-byte bruteforce (all 256 keys, scored)\n"
            "  - RSA weakness detection (small e, Fermat factoring, modulus size)\n"
            "\n"
            "Provide a cipher text, hash, or encoded string via 'input' for direct analysis,\n"
            "or a file path via 'target' for file-based analysis."
        ),
        parameters={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "File path to analyze (relative to project root).",
                },
                "input": {
                    "type": "string",
                    "description": "Direct input string to analyze (hash, ciphertext, encoded data).",
                },
                "mode": {
                    "type": "string",
                    "description": "Analysis mode: auto, identify, decode, analyze, caesar, xor, rsa.",
                    "enum": ["auto", "identify", "decode", "analyze", "caesar", "xor", "rsa"],
                },
            },
        },
    ),
    ToolDefinition(
        name="steg_analyze",
        description=(
            "Steganography analysis toolkit for hidden data in files.\n"
            "Capabilities:\n"
            "  - Magic bytes validation (17 file signatures)\n"
            "  - Strings extraction with pattern matching (flags, URLs, passwords, keys)\n"
            "  - Appended/embedded data detection (after PNG IEND, JPEG EOI)\n"
            "  - Embedded file scanning (binwalk-like: 10 signatures)\n"
            "  - Entropy analysis (per-block Shannon entropy, high-entropy regions)\n"
            "  - EXIF metadata extraction via exiftool\n"
            "\n"
            "Use for CTF challenges involving hidden data in images, PDFs, or binaries."
        ),
        parameters={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "File path to analyze (relative to project root).",
                },
                "mode": {
                    "type": "string",
                    "description": "Analysis mode: auto, magic, strings, embedded, entropy, exif.",
                    "enum": ["auto", "magic", "strings", "embedded", "entropy", "exif"],
                },
            },
            "required": ["target"],
        },
    ),
    ToolDefinition(
        name="pcap_analyze",
        description=(
            "Network packet capture (PCAP) analyzer.\n"
            "Capabilities:\n"
            "  - Protocol distribution statistics\n"
            "  - Credential sniffing (HTTP Basic, Bearer, FTP, SMTP, cookies, API keys)\n"
            "  - DNS exfiltration detection (long labels, high entropy, deep nesting)\n"
            "  - HTTP request extraction from cleartext traffic\n"
            "  - tshark fallback for pcapng/complex formats\n"
            "\n"
            "Provide a .pcap or .pcapng file for network forensics analysis."
        ),
        parameters={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Path to .pcap/.pcapng file (relative to project root).",
                },
                "mode": {
                    "type": "string",
                    "description": "Analysis mode: auto, credentials, dns, http.",
                    "enum": ["auto", "credentials", "dns", "http"],
                },
            },
            "required": ["target"],
        },
    ),
    ToolDefinition(
        name="forensic_analyze",
        description=(
            "Digital forensics toolkit for file/disk/memory analysis.\n"
            "Capabilities:\n"
            "  - File metadata extraction (timestamps, hashes MD5/SHA1/SHA256, permissions)\n"
            "  - Timestomping detection (creation date after modification date)\n"
            "  - Sensitive string extraction (flags, passwords, keys, IPs, URLs, credit cards)\n"
            "  - File carving from raw images (JPEG, PNG, PDF, ZIP, ELF, 12+ formats)\n"
            "  - EXIF metadata extraction via exiftool\n"
            "  - Volatility 3 memory forensics (process list, network, cmdline, files)\n"
            "\n"
            "Use for CTF forensics challenges, disk images, or memory dumps."
        ),
        parameters={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Path to file, disk image, or memory dump (relative to project root).",
                },
                "mode": {
                    "type": "string",
                    "description": "Analysis mode: auto, metadata, strings, carve, volatility.",
                    "enum": ["auto", "metadata", "strings", "carve", "volatility"],
                },
            },
            "required": ["target"],
        },
    ),
    ToolDefinition(
        name="binary_analyze",
        description=(
            "Binary reverse engineering toolkit.\n"
            "Capabilities:\n"
            "  - Checksec (NX, ASLR, PIE, stack canary, RELRO, Fortify detection)\n"
            "  - ELF/PE header parsing (sections, symbols, imports)\n"
            "  - String extraction with categorization (flags, passwords, format strings)\n"
            "  - Function listing (via r2pipe, nm, objdump)\n"
            "  - Disassembly of specific functions (r2pipe or objdump Intel syntax)\n"
            "  - Shared library dependency listing\n"
            "  - Format string vulnerability detection (%n in strings)\n"
            "\n"
            "Essential for CTF reversing/pwn challenges."
        ),
        parameters={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Path to binary file (relative to project root).",
                },
                "mode": {
                    "type": "string",
                    "description": "Analysis mode: auto, checksec, strings, functions, disasm, libraries.",
                    "enum": ["auto", "checksec", "strings", "functions", "disasm", "libraries"],
                },
                "function": {
                    "type": "string",
                    "description": "Function name to disassemble (for --mode disasm). Default: main.",
                },
            },
            "required": ["target"],
        },
    ),
    ToolDefinition(
        name="pwn_toolkit",
        description=(
            "Binary exploitation (pwn) assistant toolkit.\n"
            "Capabilities:\n"
            "  - Cyclic pattern generation (De Bruijn) for offset calculation\n"
            "  - Cyclic pattern offset finder (from crash EIP/RIP value)\n"
            "  - ROP gadget search (via ROPgadget/ropper)\n"
            "  - One_gadget lookup for libc (one-shot execve gadgets)\n"
            "  - Shellcode catalog (Linux x86/x64 execve, reverse shell, NOP sled)\n"
            "  - Buffer overflow offset calculator\n"
            "\n"
            "Use for CTF pwn challenges. Provide a binary for gadget/one_gadget search,\n"
            "or use cyclic/offset modes without a binary."
        ),
        parameters={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Path to binary (for gadgets/one-gadget modes).",
                },
                "mode": {
                    "type": "string",
                    "description": "Mode: auto, cyclic, gadgets, one-gadget, shellcodes, offset.",
                    "enum": ["auto", "cyclic", "gadgets", "one-gadget", "shellcodes", "offset"],
                },
                "length": {
                    "type": "integer",
                    "description": "Cyclic pattern length (default 200, for --mode cyclic).",
                },
                "find": {
                    "type": "string",
                    "description": "Value to find in pattern (hex: 0x61616178, for --mode cyclic/offset).",
                },
            },
        },
    ),
    ToolDefinition(
        name="privesc_scan",
        description=(
            "Linux privilege escalation scanner.\n"
            "Capabilities:\n"
            "  - SUID/SGID binary enumeration with GTFOBins cross-reference\n"
            "  - Dangerous Linux capabilities detection (CAP_SYS_ADMIN, etc.)\n"
            "  - Cron job analysis (world-writable scripts, root jobs)\n"
            "  - Sudo configuration audit (NOPASSWD, wildcards)\n"
            "  - Writable PATH/library path detection\n"
            "  - Kernel version vs known exploit database\n"
            "  - Docker/LXC container escape vector detection\n"
            "  - Sensitive file permission checks (/etc/shadow, SSH keys)\n"
            "\n"
            "Scans the local system by default. Use for CTF and real-world privesc."
        ),
        parameters={
            "type": "object",
            "properties": {
                "mode": {
                    "type": "string",
                    "description": "Scan mode: auto, suid, caps, cron, sudo, paths, files, container, kernel.",
                    "enum": ["auto", "suid", "caps", "cron", "sudo", "paths", "files", "container", "kernel"],
                },
            },
        },
    ),
    ToolDefinition(
        name="scan_llm_headers",
        description=(
            "Scan LLM provider endpoints for missing security headers and generate "
            "concrete exploit PoCs (clickjacking, XSS via missing CSP, HSTS downgrade).\n\n"
            "Supported providers: openai, anthropic, google, mistral, cohere, meta, "
            "huggingface, perplexity, together, fireworks, groq.\n\n"
            "Each provider has pre-configured API/console/docs URLs. The tool tests "
            "every URL and generates ready-to-use HTML/JS exploit code for each "
            "missing header.\n\n"
            "Use 'all' as provider to scan every provider at once.\n"
            "Returns findings with severity, CWE, and PoC payloads."
        ),
        parameters={
            "type": "object",
            "properties": {
                "provider": {
                    "type": "string",
                    "description": (
                        "LLM provider to scan. Use 'all' for every provider. "
                        "Options: all, openai, anthropic, google, mistral, cohere, "
                        "meta, huggingface, perplexity, together, fireworks, groq."
                    ),
                },
                "extra_urls": {
                    "type": "string",
                    "description": "Comma-separated additional URLs to test (optional).",
                },
                "save_pocs": {
                    "type": "boolean",
                    "description": "Save generated PoC files to reports/header-poc-generator/ (default true).",
                },
                "rate_limit": {
                    "type": "integer",
                    "description": "Max requests per second (default 5).",
                },
            },
            "required": ["provider"],
        },
    ),
]


# ---------------------------------------------------------------------------
# Tool executors
# ---------------------------------------------------------------------------


def _sanitize_path(path_str: str) -> Path:
    """Resolve path relative to PROJECT_ROOT, blocking traversal."""
    clean = path_str.replace("\x00", "")
    resolved = (PROJECT_ROOT / clean).resolve()
    if not str(resolved).startswith(str(PROJECT_ROOT.resolve())):
        raise ValueError(f"Path traversal blocked: {path_str}")
    return resolved


def _is_valid_url(url: str) -> bool:
    """Check if URL is http/https."""
    from urllib.parse import urlparse

    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


def _is_blocked_command(cmd: str) -> bool:
    """Check if a shell command matches blocked patterns."""
    cmd_lower = cmd.lower().strip()
    for pattern in _BLOCKED_SHELL_PATTERNS:
        if pattern in cmd_lower:
            return True
    return False


def execute_tool(name: str, arguments: dict[str, Any]) -> str:
    """Execute a tool by name and return the result as a string."""
    try:
        if name == "run_scan":
            return _exec_run_scan(arguments)
        if name == "shell_exec":
            return _exec_shell(arguments)
        if name == "read_file":
            return _exec_read_file(arguments)
        if name == "write_file":
            return _exec_write_file(arguments)
        if name == "list_findings":
            return _exec_list_findings(arguments)
        if name == "generate_report":
            return _exec_generate_report(arguments)
        if name == "list_tools":
            return _exec_list_tools(arguments)
        if name == "update_plan":
            return _exec_update_plan(arguments)
        if name == "list_dir":
            return _exec_list_dir(arguments)
        if name == "grep_search":
            return _exec_grep_search(arguments)
        if name == "file_search":
            return _exec_file_search(arguments)
        if name == "fetch_webpage":
            return _exec_fetch_webpage(arguments)
        if name == "cdp_exec":
            return _exec_cdp_exec(arguments)
        if name == "browse_page":
            return _exec_browse_page(arguments)
        if name == "workspace_write":
            return _exec_workspace_write(arguments)
        if name == "workspace_read":
            return _exec_workspace_read(arguments)
        if name == "workspace_list":
            return _exec_workspace_list(arguments)
        if name == "vault_scan":
            return _exec_vault_scan(arguments)
        if name == "vault_extract":
            return _exec_vault_extract(arguments)
        if name == "password_recover":
            return _exec_password_recover(arguments)
        if name == "password_decrypt":
            return _exec_password_decrypt(arguments)
        if name == "list_recovery_formats":
            return _exec_list_recovery_formats(arguments)
        if name == "android_adb":
            return _exec_android_adb(arguments)
        if name == "android_wifi_capture":
            return _exec_android_wifi_capture(arguments)
        if name == "android_file_transfer":
            return _exec_android_file_transfer(arguments)
        if name == "android_shell":
            return _exec_android_shell(arguments)
        # CTF / Forensics / Reversing tools
        if name == "crypto_analyze":
            return _exec_crypto_analyze(arguments)
        if name == "steg_analyze":
            return _exec_steg_analyze(arguments)
        if name == "pcap_analyze":
            return _exec_pcap_analyze(arguments)
        if name == "forensic_analyze":
            return _exec_forensic_analyze(arguments)
        if name == "binary_analyze":
            return _exec_binary_analyze(arguments)
        if name == "pwn_toolkit":
            return _exec_pwn_toolkit(arguments)
        if name == "privesc_scan":
            return _exec_privesc_scan(arguments)
        if name == "scan_llm_headers":
            return _exec_scan_llm_headers(arguments)
        return json.dumps({"error": f"Unknown tool: {name}"})
    except Exception as e:
        return json.dumps({"error": f"Tool execution failed: {e}"})


def _exec_run_scan(args: dict) -> str:
    """Execute a security scanner (Python script or external binary)."""
    tool = args.get("tool", "")
    target = args.get("target", "")
    options = args.get("options", {})

    if not tool:
        return json.dumps({"error": "tool is required"})
    if not target or not _is_valid_url(target):
        return json.dumps({"error": "target must be a valid http/https URL"})

    output_dir = PROJECT_ROOT / "reports" / tool
    output_dir.mkdir(parents=True, exist_ok=True)

    env = {
        **os.environ,
        "TARGET": target,
        "OUTPUT_DIR": str(output_dir),
        "SCAN_DATE": time.strftime("%Y-%m-%d"),
    }
    for k, v in (options or {}).items():
        safe_key = k.upper().replace("-", "_")
        if safe_key.isalnum() or "_" in safe_key:
            env[safe_key] = str(v)

    # 1) Try python-scanners directory first
    script_name = tool.replace("-", "_") + ".py"
    script = PROJECT_ROOT / "tools" / "python-scanners" / script_name
    if not script.exists():
        script = PROJECT_ROOT / "scripts" / script_name

    if script.exists():
        cmd = [sys.executable, str(script), "--target", target]
    else:
        # 2) Fall back to external binary on PATH
        binary = _find_external_binary(tool)
        if not binary:
            return json.dumps({
                "error": f"Scanner '{tool}' not found as Python script or external binary",
                "hint": "Use shell_exec to run the tool manually, or list_tools to see available tools",
            })
        cmd = _build_external_cmd(binary, tool, target, options)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=SHELL_TIMEOUT,
            cwd=str(PROJECT_ROOT),
            env=env,
        )
        output = result.stdout[:MAX_OUTPUT] if result.stdout else ""
        errors = result.stderr[:2000] if result.stderr else ""

        # Save output for later retrieval by list_findings
        out_file = output_dir / "scan-latest.json"
        try:
            # Try to save as JSON, otherwise raw text
            parsed = json.loads(output) if output.strip().startswith(("{", "[")) else None
            if parsed is not None:
                out_file.write_text(json.dumps(parsed, indent=2))
            else:
                out_file.write_text(json.dumps({
                    "tool": tool, "target": target, "raw_output": output, "exit_code": result.returncode,
                }))
        except (json.JSONDecodeError, OSError):
            pass

        return json.dumps({
            "tool": tool,
            "exit_code": result.returncode,
            "output": output,
            "errors": errors if result.returncode != 0 else "",
        })
    except subprocess.TimeoutExpired:
        return json.dumps({"tool": tool, "error": f"Timeout after {SHELL_TIMEOUT}s"})


# --- External tool command builders ---

_EXTERNAL_TOOL_COMMANDS: dict[str, list[str]] = {
    "nuclei": ["-u", "{target}", "-jsonl", "-nc", "-silent"],
    "nmap": ["-sV", "-sC", "--top-ports", "100", "-oN", "-", "{target_host}"],
    "nikto": ["-h", "{target}", "-Format", "json", "-output", "-"],
    "sqlmap": ["-u", "{target}", "--batch", "--level=1", "--risk=1", "--output-dir={output_dir}"],
    "ffuf": ["-u", "{target}/FUZZ", "-w", "/usr/share/wordlists/dirb/common.txt", "-mc", "200,301,302,403", "-json"],
    "testssl": ["--jsonfile", "{output_dir}/testssl.json", "--sneaky", "{target}"],
    "subfinder": ["-d", "{target_host}", "-silent", "-json"],
    "httpx": ["-u", "{target}", "-json", "-silent", "-tech-detect", "-status-code"],
    "katana": ["-u", "{target}", "-json", "-silent", "-depth", "2"],
    "amass": ["enum", "-passive", "-d", "{target_host}", "-json", "{output_dir}/amass.json"],
    "semgrep": ["scan", "--json", "--config=auto", "."],
    "gitleaks": ["detect", "--report-format", "json", "--report-path", "{output_dir}/gitleaks.json", "."],
    "trivy": ["fs", "--format", "json", "."],
    "feroxbuster": ["-u", "{target}", "-q", "--json"],
}


def _find_external_binary(tool: str) -> str | None:
    """Find an external binary on PATH."""
    try:
        result = subprocess.run(
            ["which", tool], capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, OSError):
        pass
    return None


def _build_external_cmd(binary: str, tool: str, target: str, options: dict) -> list[str]:
    """Build command line for an external scanner."""
    from urllib.parse import urlparse

    parsed_url = urlparse(target)
    target_host = parsed_url.hostname or target
    output_dir = str(PROJECT_ROOT / "reports" / tool)

    template = _EXTERNAL_TOOL_COMMANDS.get(tool)
    if template:
        cmd = [binary]
        for arg in template:
            cmd.append(
                arg.replace("{target}", target)
                   .replace("{target_host}", target_host)
                   .replace("{output_dir}", output_dir)
            )
        return cmd

    # Generic fallback — just pass target as last argument
    return [binary, target]


def _exec_shell(args: dict) -> str:
    """Execute a shell command."""
    command = args.get("command", "")
    cwd_rel = args.get("cwd", "")

    if not command:
        return json.dumps({"error": "command is required"})
    if _is_blocked_command(command):
        return json.dumps({"error": "Command blocked by safety filter"})

    cwd = str(PROJECT_ROOT)
    if cwd_rel:
        resolved_cwd = _sanitize_path(cwd_rel)
        if resolved_cwd.is_dir():
            cwd = str(resolved_cwd)

    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=SHELL_TIMEOUT,
            cwd=cwd,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        stdout = result.stdout[:MAX_OUTPUT] if result.stdout else ""
        stderr = result.stderr[:2000] if result.stderr else ""
        return json.dumps({
            "exit_code": result.returncode,
            "stdout": stdout,
            "stderr": stderr if result.returncode != 0 else "",
        })
    except subprocess.TimeoutExpired:
        return json.dumps({"error": f"Command timed out after {SHELL_TIMEOUT}s"})


def _exec_read_file(args: dict) -> str:
    """Read a file's contents."""
    path_str = args.get("path", "")
    tail = args.get("tail")

    if not path_str:
        return json.dumps({"error": "path is required"})

    filepath = _sanitize_path(path_str)
    if not filepath.exists():
        return json.dumps({"error": f"File not found: {path_str}"})
    if not filepath.is_file():
        return json.dumps({"error": f"Not a file: {path_str}"})

    size = filepath.stat().st_size
    if size > MAX_FILE_SIZE:
        # Read only the tail
        with open(filepath) as f:
            content = f.read()
        content = content[-MAX_FILE_SIZE:]
        return json.dumps({"path": path_str, "truncated": True, "size": size, "content": content})

    content = filepath.read_text(errors="replace")
    if tail and isinstance(tail, int) and tail > 0:
        lines = content.splitlines()
        content = "\n".join(lines[-tail:])

    return json.dumps({"path": path_str, "size": size, "content": content})


def _exec_write_file(args: dict) -> str:
    """Write content to a file."""
    path_str = args.get("path", "")
    content = args.get("content", "")

    if not path_str:
        return json.dumps({"error": "path is required"})
    if not content:
        return json.dumps({"error": "content is required"})

    filepath = _sanitize_path(path_str)
    filepath.parent.mkdir(parents=True, exist_ok=True)
    filepath.write_text(content)
    return json.dumps({"path": path_str, "size": len(content), "written": True})


def _exec_list_findings(args: dict) -> str:
    """List findings from scan reports."""
    tool_filter = args.get("tool")
    severity_filter = args.get("severity", "").lower()

    reports_dir = PROJECT_ROOT / "reports"
    if not reports_dir.exists():
        return json.dumps({"findings": [], "error": "No reports directory"})

    all_findings: list[dict] = []
    for tool_dir in sorted(reports_dir.iterdir()):
        if not tool_dir.is_dir() or tool_dir.name.startswith("."):
            continue
        if tool_filter and tool_dir.name != tool_filter:
            continue

        report_file = tool_dir / "scan-latest.json"
        if not report_file.exists():
            continue

        try:
            data = json.loads(report_file.read_text())
            findings = []
            if isinstance(data, list):
                findings = data
            elif isinstance(data, dict):
                findings = data.get("findings", data.get("vulnerabilities", data.get("results", [])))

            for f in findings:
                if not isinstance(f, dict):
                    continue
                f.setdefault("tool", tool_dir.name)
                sev = str(f.get("severity", f.get("risk", "info"))).lower()
                if severity_filter and sev != severity_filter:
                    continue
                all_findings.append({
                    "tool": f.get("tool", tool_dir.name),
                    "title": f.get("title", f.get("name", f.get("vulnerability", "Unknown"))),
                    "severity": sev,
                    "url": f.get("url", f.get("target", "")),
                    "description": str(f.get("description", ""))[:200],
                })
        except (json.JSONDecodeError, OSError):
            continue

    return json.dumps({
        "total": len(all_findings),
        "findings": all_findings[:100],  # cap at 100 to avoid context overflow
    })


def _exec_generate_report(args: dict) -> str:
    """Generate a security report and auto-save to disk + conversation workspace."""
    fmt = args.get("format", "markdown")
    target = args.get("target", "unknown")
    title = args.get("title", "Security Assessment Report")

    # Collect all findings first
    findings_json = _exec_list_findings({})
    findings_data = json.loads(findings_json)
    findings = findings_data.get("findings", [])

    if not findings:
        return json.dumps({"error": "No findings available. Run scans first."})

    report = ""
    try:
        sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
        from report_generators import PlatformReportGenerator

        report = PlatformReportGenerator.generate(
            findings=findings,
            platform=fmt,
            target=target,
            title=title,
        )
    except ImportError:
        # Fallback: generate a simple markdown report
        lines = [f"# {title}", f"\n**Target:** {target}", f"**Findings:** {len(findings)}\n"]
        for f in findings:
            lines.append(f"## [{f.get('severity', 'info').upper()}] {f.get('title', 'Unknown')}")
            lines.append(f"- **Tool:** {f.get('tool', 'unknown')}")
            lines.append(f"- **URL:** {f.get('url', 'N/A')}")
            if f.get("description"):
                lines.append(f"- **Description:** {f['description']}")
            lines.append("")
        report = "\n".join(lines)

    # --- Auto-save to reports/generated-reports/ ---
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    safe_target = re.sub(r"[^a-zA-Z0-9_-]", "_", urlparse(target).hostname or "unknown")[:40]
    filename = f"report-{timestamp}-{safe_target}-{fmt}.md"

    reports_dir = PROJECT_ROOT / "reports" / "generated-reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_path = reports_dir / filename
    try:
        report_path.write_text(report, encoding="utf-8")
    except OSError:
        pass

    saved_paths = [str(report_path.relative_to(PROJECT_ROOT))]

    # --- Also auto-save to conversation workspace if conversation_id is set ---
    conv_id = os.environ.get("CONVERSATION_ID", "")
    if conv_id:
        try:
            safe_id = _safe_conversation_id(conv_id)
            ws_dir = WORKSPACE_ROOT / safe_id
            ws_dir.mkdir(parents=True, exist_ok=True)
            ws_path = ws_dir / filename
            ws_path.write_text(report, encoding="utf-8")
            saved_paths.append(str(ws_path.relative_to(PROJECT_ROOT)))
        except OSError:
            pass

    return json.dumps({
        "format": fmt,
        "report": report[:MAX_OUTPUT],
        "saved_to": saved_paths,
        "finding_count": len(findings),
    })


def _exec_list_tools(args: dict) -> str:
    """List available scanner tools."""
    profile_filter = args.get("profile", "")

    tools_dir = PROJECT_ROOT / "tools" / "python-scanners"
    tools: list[dict] = []

    if tools_dir.exists():
        for f in sorted(tools_dir.iterdir()):
            if f.suffix == ".py" and f.name != "__init__.py" and f.name != "lib.py":
                name = f.stem.replace("_", "-")
                tools.append({"name": name, "type": "python-scanner", "path": str(f.relative_to(PROJECT_ROOT))})

    # Also list Go/external tools from known binaries
    external_tools = [
        "nuclei", "subfinder", "httpx", "katana", "amass", "dnsx",
        "nmap", "nikto", "sqlmap", "ffuf", "feroxbuster", "testssl",
        "semgrep", "gitleaks", "trufflehog", "trivy",
    ]
    for t in external_tools:
        if not profile_filter or profile_filter in ("external", "all"):
            try:
                result = subprocess.run(
                    ["which", t], capture_output=True, text=True, timeout=5,
                )
                if result.returncode == 0:
                    tools.append({"name": t, "type": "external", "path": result.stdout.strip()})
            except (subprocess.TimeoutExpired, OSError):
                pass

    if profile_filter and profile_filter not in ("external", "all"):
        tools = [t for t in tools if t.get("type") == profile_filter]

    return json.dumps({"total": len(tools), "tools": tools})


# In-memory plan state for the current session
_current_plan: dict[str, Any] = {"tasks": [], "summary": ""}


def _exec_update_plan(args: dict) -> str:
    """Create or update the task plan. Returns the full plan state."""
    tasks = args.get("tasks", [])
    summary = args.get("summary", "")

    if not tasks:
        return json.dumps({"error": "tasks array is required"})

    validated: list[dict] = []
    for t in tasks:
        if not isinstance(t, dict):
            continue
        validated.append({
            "id": t.get("id", len(validated) + 1),
            "title": str(t.get("title", "Untitled"))[:200],
            "status": t.get("status", "pending") if t.get("status") in ("pending", "in-progress", "done", "failed") else "pending",
            "result": str(t.get("result", ""))[:500] if t.get("result") else "",
        })

    _current_plan["tasks"] = validated
    if summary:
        _current_plan["summary"] = str(summary)[:1000]

    total = len(validated)
    done = sum(1 for t in validated if t["status"] == "done")
    in_progress = sum(1 for t in validated if t["status"] == "in-progress")
    failed = sum(1 for t in validated if t["status"] == "failed")

    # Also write plan to disk for UI access
    plan_file = PROJECT_ROOT / "reports" / ".agent-plan.json"
    plan_file.parent.mkdir(parents=True, exist_ok=True)
    plan_data = {
        "tasks": validated,
        "summary": _current_plan.get("summary", ""),
        "progress": {"total": total, "done": done, "in_progress": in_progress, "failed": failed},
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    try:
        plan_file.write_text(json.dumps(plan_data, indent=2))
    except OSError:
        pass

    return json.dumps({
        "plan_updated": True,
        "progress": f"{done}/{total} done" + (f", {in_progress} in progress" if in_progress else "") + (f", {failed} failed" if failed else ""),
        "tasks": validated,
    })


# ---------------------------------------------------------------------------
# VS Code-style tool executors
# ---------------------------------------------------------------------------

# Dirs/files to skip when browsing/searching
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".tox", ".mypy_cache", ".ruff_cache"}
_MAX_SEARCH_RESULTS = 50


def _exec_list_dir(args: dict) -> str:
    """List directory contents."""
    path_str = args.get("path", ".")
    depth = min(max(int(args.get("depth", 1)), 1), 3)

    dirpath = _sanitize_path(path_str)
    if not dirpath.exists():
        return json.dumps({"error": f"Directory not found: {path_str}"})
    if not dirpath.is_dir():
        return json.dumps({"error": f"Not a directory: {path_str}"})

    entries: list[str] = []

    def _walk(base: Path, current_depth: int, prefix: str = "") -> None:
        if current_depth > depth or len(entries) > 200:
            return
        try:
            items = sorted(base.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
        except PermissionError:
            return
        for item in items:
            if item.name.startswith(".") and item.name != ".env.example":
                if item.name in (".git", ".github"):
                    pass  # show these
                else:
                    continue
            if item.name in _SKIP_DIRS:
                continue
            rel = f"{prefix}{item.name}" if prefix else item.name
            if item.is_dir():
                entries.append(f"{rel}/")
                if current_depth < depth:
                    _walk(item, current_depth + 1, f"{rel}/")
            else:
                entries.append(rel)

    _walk(dirpath, 1)
    return json.dumps({"path": path_str, "count": len(entries), "entries": entries[:200]})


def _exec_grep_search(args: dict) -> str:
    """Search for text/regex in files."""
    pattern_str = args.get("pattern", "")
    path_str = args.get("path", ".")
    is_regex = bool(args.get("is_regex", False))
    include_glob = args.get("include", "")

    if not pattern_str:
        return json.dumps({"error": "pattern is required"})

    search_path = _sanitize_path(path_str)
    if not search_path.exists():
        return json.dumps({"error": f"Path not found: {path_str}"})

    if is_regex:
        try:
            compiled = re.compile(pattern_str, re.IGNORECASE)
        except re.error as e:
            return json.dumps({"error": f"Invalid regex: {e}"})
    else:
        compiled = re.compile(re.escape(pattern_str), re.IGNORECASE)

    matches: list[dict] = []
    files_searched = 0

    def _search_file(fp: Path) -> None:
        nonlocal files_searched
        if len(matches) >= _MAX_SEARCH_RESULTS:
            return
        if include_glob and not fnmatch.fnmatch(fp.name, include_glob):
            return
        if fp.stat().st_size > MAX_FILE_SIZE:
            return
        files_searched += 1
        try:
            lines = fp.read_text(errors="replace").splitlines()
            for i, line in enumerate(lines, 1):
                if compiled.search(line):
                    matches.append({
                        "file": str(fp.relative_to(PROJECT_ROOT)),
                        "line": i,
                        "text": line.strip()[:200],
                    })
                    if len(matches) >= _MAX_SEARCH_RESULTS:
                        return
        except (OSError, UnicodeDecodeError):
            pass

    if search_path.is_file():
        _search_file(search_path)
    else:
        for root, dirs, files in os.walk(search_path):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS and not d.startswith(".")]
            for fname in files:
                _search_file(Path(root) / fname)
                if len(matches) >= _MAX_SEARCH_RESULTS:
                    break

    return json.dumps({
        "pattern": pattern_str,
        "is_regex": is_regex,
        "files_searched": files_searched,
        "match_count": len(matches),
        "matches": matches,
    })


def _exec_file_search(args: dict) -> str:
    """Search for files by glob/name pattern."""
    pattern_str = args.get("pattern", "")
    path_str = args.get("path", ".")

    if not pattern_str:
        return json.dumps({"error": "pattern is required"})

    search_path = _sanitize_path(path_str)
    if not search_path.exists() or not search_path.is_dir():
        return json.dumps({"error": f"Directory not found: {path_str}"})

    results: list[str] = []

    for root, dirs, files in os.walk(search_path):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS and not d.startswith(".")]
        for fname in files:
            if fnmatch.fnmatch(fname, pattern_str) or fnmatch.fnmatch(
                str(Path(root, fname).relative_to(search_path)), pattern_str
            ):
                rel = str(Path(root, fname).relative_to(PROJECT_ROOT))
                results.append(rel)
                if len(results) >= _MAX_SEARCH_RESULTS:
                    break
        if len(results) >= _MAX_SEARCH_RESULTS:
            break

    return json.dumps({"pattern": pattern_str, "count": len(results), "files": results})


def _exec_fetch_webpage(args: dict) -> str:
    """Fetch a web page content."""
    url = args.get("url", "")
    method = args.get("method", "GET").upper()
    headers = args.get("headers") or {}

    if not url:
        return json.dumps({"error": "url is required"})
    if not _is_valid_url(url):
        return json.dumps({"error": "url must be http:// or https://"})

    # Block SSRF to internal networks
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    _blocked_hosts = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]", "metadata.google.internal"}
    if hostname in _blocked_hosts or hostname.startswith("169.254.") or hostname.startswith("10.") or hostname.startswith("192.168."):
        return json.dumps({"error": "Blocked: internal/private network address"})

    req_headers = {"User-Agent": "SecurityDashboard/1.0"}
    for k, v in headers.items():
        safe_key = str(k)[:50]
        safe_val = str(v)[:500]
        req_headers[safe_key] = safe_val

    try:
        req = Request(url, method=method, headers=req_headers)
        with urlopen(req, timeout=15) as resp:  # noqa: S310
            content_type = resp.headers.get("Content-Type", "")
            body = resp.read(MAX_OUTPUT).decode("utf-8", errors="replace")
            return json.dumps({
                "url": url,
                "status": resp.status,
                "content_type": content_type,
                "size": len(body),
                "body": body[:MAX_OUTPUT],
            })
    except URLError as e:
        return json.dumps({"error": f"Fetch failed: {e.reason}"})
    except Exception as e:
        return json.dumps({"error": f"Fetch failed: {e}"})


# ---------------------------------------------------------------------------
# CDP Browser tool executors
# ---------------------------------------------------------------------------

def _cdp_http_get(path: str) -> Any:
    """HTTP GET to CDP endpoint, returns parsed JSON."""
    import http.client

    parsed = urlparse(CDP_URL)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 9222
    conn = http.client.HTTPConnection(host, port, timeout=5)
    conn.request("GET", path)
    resp = conn.getresponse()
    data = resp.read().decode()
    conn.close()
    if resp.status != 200:
        raise ConnectionError(f"CDP HTTP {resp.status}: {data[:200]}")
    return json.loads(data)


def _cdp_ws_command(ws_url: str, method: str, params: dict | None = None, timeout: float = 15.0) -> dict:
    """Send a CDP command via WebSocket and return result."""
    try:
        import websocket  # websocket-client
    except ImportError:
        return {"error": "websocket-client not installed. Run: pip install websocket-client"}

    ws = websocket.create_connection(ws_url, timeout=timeout)
    msg_id = 1
    payload = {"id": msg_id, "method": method}
    if params:
        payload["params"] = params
    ws.send(json.dumps(payload))

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        raw = ws.recv()
        resp = json.loads(raw)
        if resp.get("id") == msg_id:
            ws.close()
            if "error" in resp:
                return {"error": resp["error"].get("message", str(resp["error"]))}
            return resp.get("result", {})
    ws.close()
    return {"error": f"CDP timeout waiting for {method}"}


def _get_cdp_page_ws() -> str | None:
    """Get WebSocket URL of the first page target."""
    try:
        targets = _cdp_http_get("/json")
        pages = [t for t in targets if t.get("type") == "page"]
        if pages:
            return pages[0].get("webSocketDebuggerUrl", "")
    except Exception:
        return None
    return None


def _exec_cdp_exec(args: dict) -> str:
    """Execute a raw CDP command."""
    method = args.get("method", "")
    params = args.get("params") or {}

    if not method:
        return json.dumps({"error": "method is required"})

    # Block dangerous CDP methods
    _blocked_methods = {"Browser.close", "Target.disposeBrowserContext", "SystemInfo.getProcessInfo"}
    if method in _blocked_methods:
        return json.dumps({"error": f"CDP method blocked: {method}"})

    ws_url = _get_cdp_page_ws()
    if not ws_url:
        return json.dumps({
            "error": "CDP not available. Launch Chrome with --remote-debugging-port=9222 or use the dashboard CDP panel.",
            "hint": "POST /api/cdp/launch to auto-launch Chrome headless",
        })

    result = _cdp_ws_command(ws_url, method, params)
    # Truncate large results
    result_str = json.dumps(result, default=str)
    if len(result_str) > MAX_OUTPUT:
        return json.dumps({"result": result_str[:MAX_OUTPUT], "truncated": True})
    return json.dumps({"result": result})


def _exec_browse_page(args: dict) -> str:
    """Navigate to URL in CDP browser and return rendered content."""
    url = args.get("url", "")
    wait_ms = min(max(int(args.get("wait_ms", 3000)), 500), 15000)
    selector = args.get("extract_selector", "")

    if not url or not _is_valid_url(url):
        return json.dumps({"error": "url must be a valid http:// or https:// URL"})

    # Block SSRF
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    _blocked = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]", "metadata.google.internal"}
    if hostname in _blocked or hostname.startswith("169.254.") or hostname.startswith("10.") or hostname.startswith("192.168."):
        return json.dumps({"error": "Blocked: internal/private network address"})

    ws_url = _get_cdp_page_ws()
    if not ws_url:
        return json.dumps({
            "error": "CDP not available. Launch Chrome first.",
            "hint": "POST /api/cdp/launch to auto-launch Chrome headless",
        })

    # Navigate
    nav_result = _cdp_ws_command(ws_url, "Page.navigate", {"url": url})
    if "error" in nav_result:
        return json.dumps({"error": f"Navigation failed: {nav_result['error']}"})

    # Wait for page load
    time.sleep(wait_ms / 1000.0)

    # Extract page info
    title_result = _cdp_ws_command(ws_url, "Runtime.evaluate", {
        "expression": "document.title",
        "returnByValue": True,
    })
    title = title_result.get("result", {}).get("value", "")

    # Extract text content or specific selector
    if selector:
        safe_sel = selector.replace("\\", "\\\\").replace("'", "\\'")
        js_expr = (
            f"Array.from(document.querySelectorAll('{safe_sel}'))"
            ".map(el => el.textContent.trim()).filter(t => t).join('\\n')"
        )
    else:
        js_expr = "document.body?.innerText || document.documentElement?.innerText || ''"

    content_result = _cdp_ws_command(ws_url, "Runtime.evaluate", {
        "expression": js_expr,
        "returnByValue": True,
    })
    content = content_result.get("result", {}).get("value", "")

    # Capture console errors
    console_result = _cdp_ws_command(ws_url, "Runtime.evaluate", {
        "expression": """
        (function() {
            var u = window.location.href;
            var errs = [];
            if (window.__consoleErrors) errs = window.__consoleErrors;
            return JSON.stringify({url: u, errors: errs.slice(-10)});
        })()
        """,
        "returnByValue": True,
    })
    page_info = {}
    try:
        page_info = json.loads(console_result.get("result", {}).get("value", "{}"))
    except (json.JSONDecodeError, TypeError):
        pass

    text = str(content)[:MAX_OUTPUT]
    return json.dumps({
        "url": url,
        "title": title,
        "content_length": len(text),
        "content": text,
        "console_errors": page_info.get("errors", []),
        "selector": selector or None,
    })


# ---------------------------------------------------------------------------
# Per-conversation workspace tool executors
# ---------------------------------------------------------------------------

def _safe_conversation_id(conv_id: str) -> str:
    """Sanitize conversation ID to a safe directory name."""
    # Accept alphanumeric, hyphens, underscores only
    safe = re.sub(r"[^a-zA-Z0-9_-]", "", str(conv_id)[:64])
    if not safe:
        safe = hashlib.sha256(conv_id.encode()).hexdigest()[:16]
    return safe


def _workspace_path(conv_id: str) -> Path:
    """Get the workspace directory for a conversation."""
    safe_id = _safe_conversation_id(conv_id)
    ws_dir = WORKSPACE_ROOT / safe_id
    ws_dir.mkdir(parents=True, exist_ok=True)
    return ws_dir


def _sanitize_workspace_filename(ws_dir: Path, filename: str) -> Path:
    """Resolve a filename within the workspace, blocking traversal."""
    clean = filename.replace("\x00", "").replace("\\", "/")
    resolved = (ws_dir / clean).resolve()
    if not str(resolved).startswith(str(ws_dir.resolve())):
        raise ValueError(f"Path traversal blocked: {filename}")
    return resolved


def _exec_workspace_write(args: dict) -> str:
    """Write a file to the conversation workspace."""
    conv_id = args.get("conversation_id", "")
    filename = args.get("filename", "")
    content = args.get("content", "")

    if not conv_id:
        return json.dumps({"error": "conversation_id is required"})
    if not filename:
        return json.dumps({"error": "filename is required"})
    if not content:
        return json.dumps({"error": "content is required"})

    ws_dir = _workspace_path(conv_id)
    try:
        filepath = _sanitize_workspace_filename(ws_dir, filename)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    filepath.parent.mkdir(parents=True, exist_ok=True)
    filepath.write_text(content)

    return json.dumps({
        "written": True,
        "workspace": _safe_conversation_id(conv_id),
        "filename": filename,
        "size": len(content),
        "full_path": str(filepath.relative_to(PROJECT_ROOT)),
    })


def _exec_workspace_read(args: dict) -> str:
    """Read a file from the conversation workspace."""
    conv_id = args.get("conversation_id", "")
    filename = args.get("filename", "")

    if not conv_id:
        return json.dumps({"error": "conversation_id is required"})
    if not filename:
        return json.dumps({"error": "filename is required"})

    ws_dir = _workspace_path(conv_id)
    try:
        filepath = _sanitize_workspace_filename(ws_dir, filename)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    if not filepath.exists():
        return json.dumps({"error": f"File not found: {filename}"})
    if not filepath.is_file():
        return json.dumps({"error": f"Not a file: {filename}"})

    size = filepath.stat().st_size
    if size > MAX_FILE_SIZE:
        content = filepath.read_text(errors="replace")[-MAX_FILE_SIZE:]
        return json.dumps({"filename": filename, "truncated": True, "size": size, "content": content})

    content = filepath.read_text(errors="replace")
    return json.dumps({"filename": filename, "size": size, "content": content})


def _exec_workspace_list(args: dict) -> str:
    """List files in the conversation workspace."""
    conv_id = args.get("conversation_id", "")

    if not conv_id:
        return json.dumps({"error": "conversation_id is required"})

    ws_dir = _workspace_path(conv_id)
    if not ws_dir.exists():
        return json.dumps({"conversation_id": conv_id, "files": [], "count": 0})

    files: list[dict] = []
    for root, _dirs, filenames in os.walk(ws_dir):
        for fname in sorted(filenames):
            fp = Path(root) / fname
            rel = str(fp.relative_to(ws_dir))
            files.append({
                "name": rel,
                "size": fp.stat().st_size,
                "modified": time.strftime("%Y-%m-%d %H:%M", time.localtime(fp.stat().st_mtime)),
            })
            if len(files) >= 100:
                break

    return json.dumps({
        "conversation_id": _safe_conversation_id(conv_id),
        "count": len(files),
        "files": files,
    })


# ---------------------------------------------------------------------------
# Password Recovery tool executors
# ---------------------------------------------------------------------------

# Allowed scan paths — only user home + /tmp
_RECOVERY_ALLOWED_ROOTS: set[str] = set()


def _recovery_path_ok(p: str) -> bool:
    """Check that a path is under $HOME or /tmp (no traversal)."""
    if ".." in p or "\x00" in p:
        return False
    resolved = os.path.realpath(p)
    home = os.path.realpath(os.path.expanduser("~"))
    tmp = os.path.realpath("/tmp")
    return resolved.startswith(home) or resolved.startswith(tmp)


def _run_recovery_cli(args: list[str], timeout: int = RECOVERY_TIMEOUT) -> dict:
    """Run the recovery CLI and return parsed output."""
    if not RECOVERY_CLI.exists():
        return {"error": "Recovery engine not found. Run project setup first."}

    node_bin = "node"
    cmd = [node_bin, str(RECOVERY_CLI)] + args

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(RECOVERY_ENGINE_ROOT),
            env={**os.environ, "NODE_OPTIONS": "--max-old-space-size=4096"},
        )
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        # Try to parse JSON output
        if stdout and stdout.startswith(("{", "[")):
            try:
                return {"ok": True, "data": json.loads(stdout), "exit_code": result.returncode}
            except json.JSONDecodeError:
                pass

        return {
            "ok": result.returncode == 0,
            "stdout": stdout[:MAX_OUTPUT],
            "stderr": stderr[:2000] if result.returncode != 0 else "",
            "exit_code": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"error": f"Recovery operation timed out after {timeout}s"}
    except FileNotFoundError:
        return {"error": "Node.js not found. Ensure node is on PATH."}


def _exec_vault_scan(args: dict) -> str:
    """Scan for encrypted files on the machine."""
    scan_path = args.get("scan_path", "")
    deep = bool(args.get("deep", False))

    cli_args: list[str] = []

    if deep:
        cli_args.append("deep-scan")
    else:
        cli_args.append("scan")

    # scan/deep-scan output results to a directory via -o
    if scan_path:
        if not _recovery_path_ok(scan_path):
            return json.dumps({"error": "Scan path must be under $HOME or /tmp, no traversal allowed."})
        cli_args.extend(["-o", scan_path])

    # Category filter
    category = args.get("category", "")
    if category:
        _VALID_CATS = {"wallet", "password-manager", "archive", "document", "disk", "network", "mobile"}
        if category not in _VALID_CATS:
            return json.dumps({"error": f"Invalid category. Must be one of: {', '.join(sorted(_VALID_CATS))}"})
        cli_args.extend(["--category", category])

    # Format filter
    fmt = args.get("format", "")
    if fmt:
        cli_args.extend(["--format", fmt])

    cli_args.append("--json")
    result = _run_recovery_cli(cli_args, timeout=120)
    return json.dumps(result)


def _exec_vault_extract(args: dict) -> str:
    """Extract encrypted vault from browser storage."""
    browser = args.get("browser", "chrome")
    output_path = args.get("output_path", "")
    extract_all = bool(args.get("extract_all", False))

    if browser not in ("chrome", "firefox", "brave", "edge"):
        return json.dumps({"error": "browser must be one of: chrome, firefox, brave, edge"})

    if extract_all:
        cli_args = ["extract-all"]
        if output_path:
            out = (PROJECT_ROOT / output_path).resolve()
            if not str(out).startswith(str(PROJECT_ROOT.resolve())):
                return json.dumps({"error": "Output path traversal blocked."})
            cli_args.extend(["-o", str(out)])

        # Category filter
        category = args.get("category", "")
        if category:
            _VALID_CATS = {"wallet", "password-manager", "archive", "document", "disk", "network", "mobile"}
            if category not in _VALID_CATS:
                return json.dumps({"error": f"Invalid category. Must be one of: {', '.join(sorted(_VALID_CATS))}"})
            cli_args.extend(["--category", category])

        # Format filter
        fmt = args.get("format", "")
        if fmt:
            cli_args.extend(["--format", fmt])
    else:
        cli_args = ["extract"]
        if output_path:
            if ".." in output_path or "\x00" in output_path:
                return json.dumps({"error": "Path traversal blocked."})
            out_file = PROJECT_ROOT / output_path
            out_file.parent.mkdir(parents=True, exist_ok=True)
            cli_args.extend(["-o", str(out_file)])

    result = _run_recovery_cli(cli_args, timeout=60)
    return json.dumps(result)


def _exec_password_recover(args: dict) -> str:
    """Launch password recovery against an encrypted file."""
    target_file = args.get("target_file", "")
    strategy = args.get("strategy", "all")
    profile = args.get("profile", {})
    wordlist = args.get("wordlist", "")
    charset = args.get("charset", "alphanumeric")
    min_length = int(args.get("min_length", 4))
    max_length = int(args.get("max_length", 12))
    threads = args.get("threads")

    if not target_file:
        return json.dumps({"error": "target_file is required"})

    # Resolve and validate target path
    resolved = (PROJECT_ROOT / target_file).resolve()
    if not str(resolved).startswith(str(PROJECT_ROOT.resolve())):
        # Also allow paths under $HOME
        if not _recovery_path_ok(target_file):
            return json.dumps({"error": "Target file path must be under project root or $HOME."})
        resolved = Path(os.path.realpath(target_file))

    if not resolved.exists():
        return json.dumps({"error": f"Target file not found: {target_file}"})

    # Forced format override (skip auto-detect)
    forced_format = args.get("format", "")

    # Determine if this is a vault.json (MetaMask) or a generic file
    is_vault = str(resolved).endswith(".json") or str(resolved).endswith("vault.json")
    if is_vault and not forced_format:
        cli_args = ["crack", "-v", str(resolved)]
    else:
        cli_args = ["crack-file", "-f", str(resolved)]

    if forced_format:
        cli_args.extend(["--format", forced_format])

    # Strategy
    if strategy in ("profile", "dictionary", "bruteforce", "all"):
        cli_args.extend(["-s", strategy])

    # Profile (write to temp file)
    if profile and isinstance(profile, dict):
        clean_profile: dict[str, list[str]] = {}
        allowed_keys = {"names", "dates", "words", "partials", "oldPasswords"}
        total_tokens = 0
        for k, v in profile.items():
            if k not in allowed_keys:
                continue
            if not isinstance(v, list):
                continue
            entries = []
            for item in v:
                if not isinstance(item, str) or ".." in item or "\x00" in item:
                    continue
                trimmed = item.strip()[:200]
                if trimmed:
                    entries.append(trimmed)
                    total_tokens += 1
                    if total_tokens >= 500:
                        break
            if entries:
                clean_profile[k] = entries
            if total_tokens >= 500:
                break

        if clean_profile:
            profile_path = PROJECT_ROOT / "reports" / ".recovery-profile.json"
            profile_path.parent.mkdir(parents=True, exist_ok=True)
            profile_path.write_text(json.dumps(clean_profile))
            cli_args.extend(["-P", str(profile_path)])

    # Wordlist
    if wordlist:
        wl_path = (PROJECT_ROOT / wordlist).resolve()
        if not str(wl_path).startswith(str(PROJECT_ROOT.resolve())):
            return json.dumps({"error": "Wordlist path must be under project root."})
        if wl_path.exists():
            cli_args.extend(["-w", str(wl_path)])

    # Charset & lengths
    if charset in ("lowercase", "alpha", "alphanumeric", "full"):
        cli_args.extend(["--charset", charset])
    cli_args.extend(["--min-length", str(max(1, min(min_length, 32)))])
    cli_args.extend(["--max-length", str(max(1, min(max_length, 64)))])

    # Threads
    if threads and isinstance(threads, int) and 1 <= threads <= 32:
        cli_args.extend(["-t", str(threads)])

    result = _run_recovery_cli(cli_args, timeout=RECOVERY_TIMEOUT)
    return json.dumps(result)


def _exec_password_decrypt(args: dict) -> str:
    """Decrypt an encrypted file with a known password."""
    vault_file = args.get("vault_file", "")
    password = args.get("password", "")

    if not vault_file:
        return json.dumps({"error": "vault_file is required"})
    if not password:
        return json.dumps({"error": "password is required"})

    # Validate path
    resolved = (PROJECT_ROOT / vault_file).resolve()
    if not str(resolved).startswith(str(PROJECT_ROOT.resolve())):
        if not _recovery_path_ok(vault_file):
            return json.dumps({"error": "Vault file path must be under project root or $HOME."})
        resolved = Path(os.path.realpath(vault_file))

    if not resolved.exists():
        return json.dumps({"error": f"File not found: {vault_file}"})

    cli_args = ["decrypt", "-v", str(resolved), "-p", password]
    result = _run_recovery_cli(cli_args, timeout=60)

    # Mask the password in the result to avoid leaking through logs
    result_str = json.dumps(result)
    masked = result_str.replace(password, "****" + password[-2:] if len(password) > 2 else "****")
    return masked


def _exec_list_recovery_formats(args: dict) -> str:
    """List all supported encrypted file formats."""
    cli_args = ["formats"]
    category = args.get("category", "")
    if category:
        cli_args.extend(["--category", category])
    result = _run_recovery_cli(cli_args, timeout=15)
    return json.dumps(result)


# ---------------------------------------------------------------------------
# Android ADB Bridge tool executors
# ---------------------------------------------------------------------------

# Safety: blocked ADB shell patterns
_BLOCKED_ADB_PATTERNS = [
    "rm -rf /",
    "dd if=",
    "mkfs.",
    "reboot",
    "flash",
    "fastboot",
    "wipe",
    "factory",
    "format /",
    "svc power shutdown",
]

# Max capture duration (seconds)
_MAX_CAPTURE_DURATION = 600

# Capture output directory
_CAPTURES_DIR = PROJECT_ROOT / "reports" / "captures"
_ANDROID_DIR = PROJECT_ROOT / "reports" / "android"


def _find_adb() -> str | None:
    """Find ADB binary path."""
    for candidate in ["adb", os.path.expanduser("~/Library/Android/sdk/platform-tools/adb"),
                       "/opt/homebrew/bin/adb", "/usr/local/bin/adb"]:
        try:
            result = subprocess.run(
                [candidate, "version"], capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                return candidate
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None


def _adb_cmd(args: list[str], serial: str = "", timeout: int = 30) -> dict:
    """Run an ADB command and return structured output."""
    adb = _find_adb()
    if not adb:
        return {
            "error": "ADB not found. Install with: brew install android-platform-tools",
            "hint": "Then enable USB/Wireless debugging on the Android device (Developer Options)",
        }

    cmd: list[str] = [adb]
    if serial:
        # Validate serial against injection
        if not re.match(r"^[\w.:@\[\]-]{1,100}$", serial):
            return {"error": "Invalid device serial format."}
        cmd.extend(["-s", serial])
    cmd.extend(args)

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            env={**os.environ, "ADB_VENDOR_KEYS": os.path.expanduser("~/.android")},
        )
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()
        return {
            "ok": result.returncode == 0,
            "stdout": stdout[:MAX_OUTPUT],
            "stderr": stderr[:2000] if result.returncode != 0 else "",
            "exit_code": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"error": f"ADB command timed out after {timeout}s"}
    except FileNotFoundError:
        return {"error": "ADB binary not found."}


def _exec_android_adb(args: dict) -> str:
    """Manage ADB device connections."""
    action = args.get("action", "devices")
    target = args.get("target", "")
    serial = args.get("serial", "")

    if action == "devices":
        result = _adb_cmd(["devices", "-l"])
        if result.get("ok"):
            lines = result["stdout"].splitlines()
            devices = []
            for line in lines[1:]:  # skip header
                parts = line.split()
                if len(parts) >= 2:
                    devices.append({
                        "serial": parts[0],
                        "state": parts[1],
                        "info": " ".join(parts[2:]) if len(parts) > 2 else "",
                    })
            return json.dumps({"devices": devices, "count": len(devices)})
        return json.dumps(result)

    if action == "connect":
        if not target:
            return json.dumps({"error": "target (ip:port) required for connect"})
        # Validate IP:port format
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d{1,5})?$", target):
            return json.dumps({"error": "target must be IP:port (e.g. 192.168.1.100:5555)"})
        return json.dumps(_adb_cmd(["connect", target]))

    if action == "pair":
        if not target:
            return json.dumps({"error": "target (ip:port) required for pair"})
        pairing_code = args.get("pairing_code", "")
        if not pairing_code or not re.match(r"^\d{6}$", pairing_code):
            return json.dumps({"error": "pairing_code must be a 6-digit code from the device's Wireless Debugging dialog"})
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}$", target):
            return json.dumps({"error": "target must be IP:port for pairing"})
        return json.dumps(_adb_cmd(["pair", target, pairing_code]))

    if action == "status":
        serial_target = target or serial
        cmd_args = ["shell", "getprop ro.product.model"]
        r_model = _adb_cmd(cmd_args, serial=serial_target)
        r_version = _adb_cmd(["shell", "getprop ro.build.version.release"], serial=serial_target)
        r_root = _adb_cmd(["shell", "su -c id"], serial=serial_target, timeout=10)
        r_iface = _adb_cmd(["shell", "ip link show"], serial=serial_target)

        return json.dumps({
            "model": r_model.get("stdout", "unknown"),
            "android_version": r_version.get("stdout", "unknown"),
            "rooted": "uid=0" in r_root.get("stdout", ""),
            "root_output": r_root.get("stdout", r_root.get("stderr", ""))[:200],
            "interfaces": r_iface.get("stdout", "")[:2000],
        })

    if action == "forward":
        local_port = args.get("local_port", 0)
        remote_port = args.get("remote_port", 0)
        if not (1024 <= local_port <= 65535) or not (1 <= remote_port <= 65535):
            return json.dumps({"error": "local_port (1024-65535) and remote_port (1-65535) required"})
        return json.dumps(_adb_cmd(
            ["forward", f"tcp:{local_port}", f"tcp:{remote_port}"],
            serial=serial,
        ))

    return json.dumps({"error": f"Unknown action: {action}"})


def _exec_android_wifi_capture(args: dict) -> str:
    """WiFi handshake capture via Android device."""
    action = args.get("action", "scan")
    serial = args.get("serial", "")
    interface = args.get("interface", "wlan0")
    bssid = args.get("bssid", "")
    channel = args.get("channel", 0)
    duration = min(max(int(args.get("duration", 60)), 5), _MAX_CAPTURE_DURATION)
    output_file = args.get("output_file", "")

    # Validate interface name (prevent injection)
    if not re.match(r"^[a-zA-Z0-9_-]{1,20}$", interface):
        return json.dumps({"error": "Invalid interface name."})

    # Validate BSSID if provided
    if bssid and not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", bssid):
        return json.dumps({"error": "BSSID must be a valid MAC address (AA:BB:CC:DD:EE:FF)"})

    _CAPTURES_DIR.mkdir(parents=True, exist_ok=True)

    if action == "scan":
        # Scan visible WiFi networks
        r = _adb_cmd(
            ["shell", "su", "-c", f"iwlist {interface} scan 2>/dev/null || iw dev {interface} scan 2>/dev/null"],
            serial=serial, timeout=30,
        )
        if not r.get("ok"):
            # Fallback: use Android's standard WiFi scan
            r = _adb_cmd(
                ["shell", "dumpsys wifi | grep -E 'SSID|BSSID|freq|level|capabilities'"],
                serial=serial, timeout=15,
            )
        return json.dumps(r)

    if action == "capture":
        if not bssid:
            return json.dumps({"error": "bssid required for capture. Run scan first to find target AP."})

        # Generate output filename
        ts = time.strftime("%Y%m%d_%H%M%S")
        safe_bssid = bssid.replace(":", "")
        device_capture = f"/data/local/tmp/capture_{safe_bssid}_{ts}.pcap"

        # Check if tcpdump or airodump-ng is available
        tool_check = _adb_cmd(
            ["shell", "su", "-c", "which tcpdump 2>/dev/null || which airodump-ng 2>/dev/null"],
            serial=serial, timeout=10,
        )
        capture_tool = tool_check.get("stdout", "").strip().split("\n")[0]

        if "airodump-ng" in capture_tool:
            # Use aircrack-ng suite (preferred for WPA handshake capture)
            ch_arg = f"-c {channel}" if channel else ""
            capture_cmd = (
                f"su -c 'airmon-ng start {interface} 2>/dev/null; "
                f"timeout {duration} airodump-ng --bssid {bssid} {ch_arg} "
                f"-w /data/local/tmp/capture_{safe_bssid}_{ts} --output-format pcap {interface}mon 2>&1'"
            )
        elif "tcpdump" in capture_tool:
            # Fallback to tcpdump (captures all traffic, needs post-processing)
            capture_cmd = (
                f"su -c 'timeout {duration} tcpdump -i {interface} -w {device_capture} "
                f"-c 50000 \"ether host {bssid}\" 2>&1'"
            )
        else:
            return json.dumps({
                "error": "No capture tool found on device. Install tcpdump or aircrack-ng.",
                "hint": (
                    "On rooted device with Magisk + Termux:\n"
                    "  pkg install root-repo && pkg install tcpdump\n"
                    "  OR: pkg install aircrack-ng\n"
                    "Use android_shell to install."
                ),
            })

        # Start capture in background on device
        _adb_cmd(["shell", capture_cmd], serial=serial, timeout=duration + 10)

        # Pull capture file
        local_name = output_file or f"capture_{safe_bssid}_{ts}.pcap"
        if ".." in local_name or "/" in local_name or "\x00" in local_name:
            return json.dumps({"error": "Invalid output filename."})
        local_dest = str(_CAPTURES_DIR / local_name)

        # Try to find the actual capture file (airodump adds suffixes)
        find_result = _adb_cmd(
            ["shell", f"ls -la /data/local/tmp/capture_{safe_bssid}_{ts}* 2>/dev/null"],
            serial=serial, timeout=10,
        )
        # Pull the first matching file
        device_files = [
            line.split()[-1] for line in find_result.get("stdout", "").splitlines()
            if f"capture_{safe_bssid}_{ts}" in line and line.split()
        ]

        if not device_files:
            device_files = [device_capture]

        pulled: list[str] = []
        for df in device_files[:5]:  # max 5 files
            pull_r = _adb_cmd(["pull", df, local_dest], serial=serial, timeout=60)
            if pull_r.get("ok"):
                pulled.append(local_dest)

        return json.dumps({
            "ok": bool(pulled),
            "capture_files": pulled,
            "device_files": device_files[:5],
            "bssid": bssid,
            "channel": channel,
            "duration": duration,
            "next_step": f"Use password_recover(target_file='reports/captures/{local_name}', format='wifi') to crack the WPA handshake",
        })

    if action == "deauth":
        if not bssid:
            return json.dumps({"error": "bssid required for deauth attack."})
        # aireplay-ng deauth
        deauth_cmd = (
            f"su -c 'aireplay-ng --deauth 5 -a {bssid} {interface}mon 2>&1 || "
            f"aireplay-ng --deauth 5 -a {bssid} {interface} 2>&1'"
        )
        r = _adb_cmd(["shell", deauth_cmd], serial=serial, timeout=15)
        return json.dumps(r)

    if action == "status":
        r = _adb_cmd(
            ["shell", "su -c 'ps -A | grep -iE \"tcpdump|airodump|airmon\" 2>/dev/null'"],
            serial=serial, timeout=10,
        )
        # also check capture files
        files_r = _adb_cmd(
            ["shell", "ls -la /data/local/tmp/capture_* 2>/dev/null"],
            serial=serial, timeout=10,
        )
        return json.dumps({
            "running_processes": r.get("stdout", ""),
            "capture_files_on_device": files_r.get("stdout", ""),
        })

    if action == "stop":
        # Kill capture processes
        _adb_cmd(
            ["shell", "su -c 'pkill -f tcpdump; pkill -f airodump; airmon-ng stop wlan0mon 2>/dev/null'"],
            serial=serial, timeout=10,
        )

        # Pull any capture files
        ls_r = _adb_cmd(
            ["shell", "ls /data/local/tmp/capture_* 2>/dev/null"],
            serial=serial, timeout=10,
        )
        pulled = []
        _CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
        for line in ls_r.get("stdout", "").splitlines():
            fname = line.strip().split("/")[-1]
            if fname and re.match(r"^capture_[\w.-]+$", fname):
                local_dest = str(_CAPTURES_DIR / fname)
                r = _adb_cmd(["pull", line.strip(), local_dest], serial=serial, timeout=60)
                if r.get("ok"):
                    pulled.append(local_dest)

        return json.dumps({
            "ok": True,
            "stopped": True,
            "pulled_files": pulled,
            "next_step": "Use password_recover(target_file='<capture_file>', format='wifi') to crack" if pulled else "No capture files found on device.",
        })

    return json.dumps({"error": f"Unknown action: {action}"})


def _exec_android_file_transfer(args: dict) -> str:
    """Transfer files between local machine and Android device."""
    action = args.get("action", "ls")
    device_path = args.get("device_path", "")
    local_path = args.get("local_path", "")
    serial = args.get("serial", "")

    if not device_path:
        return json.dumps({"error": "device_path is required"})

    # Block path traversal on device path
    if ".." in device_path or "\x00" in device_path:
        return json.dumps({"error": "Path traversal blocked in device_path."})

    if action == "ls":
        r = _adb_cmd(["shell", f"ls -la {device_path}"], serial=serial, timeout=15)
        return json.dumps(r)

    if action == "pull":
        _ANDROID_DIR.mkdir(parents=True, exist_ok=True)
        if local_path:
            if ".." in local_path or "\x00" in local_path:
                return json.dumps({"error": "Path traversal blocked in local_path."})
            dest = (PROJECT_ROOT / local_path).resolve()
            if not str(dest).startswith(str(PROJECT_ROOT.resolve())):
                return json.dumps({"error": "Destination must be under project root."})
            dest.parent.mkdir(parents=True, exist_ok=True)
            local_dest = str(dest)
        else:
            fname = device_path.rstrip("/").split("/")[-1]
            if not fname or not re.match(r"^[\w.\-]+$", fname):
                fname = f"pulled_{int(time.time())}"
            local_dest = str(_ANDROID_DIR / fname)

        r = _adb_cmd(["pull", device_path, local_dest], serial=serial, timeout=120)
        if r.get("ok"):
            r["local_file"] = local_dest
            try:
                r["size"] = os.path.getsize(local_dest)
            except OSError:
                pass
        return json.dumps(r)

    if action == "push":
        if not local_path:
            return json.dumps({"error": "local_path required for push action"})
        if ".." in local_path or "\x00" in local_path:
            return json.dumps({"error": "Path traversal blocked in local_path."})
        src = (PROJECT_ROOT / local_path).resolve()
        if not str(src).startswith(str(PROJECT_ROOT.resolve())):
            return json.dumps({"error": "Source must be under project root."})
        if not src.exists():
            return json.dumps({"error": f"Local file not found: {local_path}"})
        r = _adb_cmd(["push", str(src), device_path], serial=serial, timeout=120)
        return json.dumps(r)

    return json.dumps({"error": f"Unknown action: {action}"})


def _exec_android_shell(args: dict) -> str:
    """Execute shell command on connected Android device."""
    command = args.get("command", "")
    serial = args.get("serial", "")
    as_root = bool(args.get("as_root", False))

    if not command:
        return json.dumps({"error": "command is required"})

    # Length limit
    if len(command) > 2000:
        return json.dumps({"error": "Command too long (max 2000 chars)."})

    # Block dangerous patterns
    cmd_lower = command.lower()
    for pattern in _BLOCKED_ADB_PATTERNS:
        if pattern in cmd_lower:
            return json.dumps({"error": f"Blocked dangerous command pattern: {pattern}"})

    # Prevent shell metachar injection — allow only reasonable chars
    # We pass the command as a single string to adb shell, so validate carefully
    if "\x00" in command:
        return json.dumps({"error": "Null bytes not allowed."})

    if as_root:
        # Escape single quotes in command for su -c wrapping
        escaped = command.replace("'", "'\\''")
        shell_args = ["shell", "su", "-c", escaped]
    else:
        shell_args = ["shell", command]

    r = _adb_cmd(shell_args, serial=serial, timeout=30)
    return json.dumps(r)


# ---------------------------------------------------------------------------
# CTF / Forensics / Reversing tool executors
# ---------------------------------------------------------------------------

_SCANNERS_DIR = PROJECT_ROOT / "tools" / "python-scanners"


def _run_python_scanner(script_name: str, cli_args: list[str]) -> str:
    """Run a Python scanner from tools/python-scanners/ and return results."""
    script = _SCANNERS_DIR / script_name
    if not script.exists():
        return json.dumps({"error": f"Scanner not found: {script_name}"})

    output_dir = PROJECT_ROOT / "reports" / script_name.replace(".py", "").replace("_", "-")
    output_dir.mkdir(parents=True, exist_ok=True)

    env = {
        **os.environ,
        "OUTPUT_DIR": str(output_dir),
        "SCAN_DATE": time.strftime("%Y-%m-%d"),
    }

    try:
        result = subprocess.run(
            [sys.executable, str(script)] + cli_args,
            capture_output=True,
            text=True,
            timeout=SHELL_TIMEOUT,
            cwd=str(_SCANNERS_DIR),
            env=env,
        )
        output = result.stdout[:MAX_OUTPUT] if result.stdout else ""
        errors = result.stderr[:2000] if result.stderr else ""

        # Try to load the report file for structured output
        report_file = output_dir / "scan-latest.json"
        if report_file.exists():
            try:
                report_data = json.loads(report_file.read_text())
                return json.dumps({
                    "exit_code": result.returncode,
                    "findings": report_data.get("findings", report_data) if isinstance(report_data, dict) else report_data,
                    "output": output[:2000],
                    "errors": errors if result.returncode != 0 else "",
                })
            except json.JSONDecodeError:
                pass

        return json.dumps({
            "exit_code": result.returncode,
            "output": output,
            "errors": errors if result.returncode != 0 else "",
        })
    except subprocess.TimeoutExpired:
        return json.dumps({"error": f"Scanner timed out after {SHELL_TIMEOUT}s"})


def _exec_crypto_analyze(args: dict) -> str:
    """Run crypto analysis toolkit."""
    target = args.get("target", "")
    input_str = args.get("input", "")
    mode = args.get("mode", "auto")

    cli_args = ["--mode", mode]
    if target:
        cli_args.extend(["--target", str(_sanitize_path(target))])
    elif input_str:
        cli_args.extend(["--target", "/dev/null", "--input", input_str])
    else:
        return json.dumps({"error": "Either 'target' (file path) or 'input' (string) is required"})

    return _run_python_scanner("crypto_analyzer.py", cli_args)


def _exec_steg_analyze(args: dict) -> str:
    """Run steganography analysis."""
    target = args.get("target", "")
    mode = args.get("mode", "auto")

    if not target:
        return json.dumps({"error": "target file path is required"})

    filepath = _sanitize_path(target)
    return _run_python_scanner("steg_analyzer.py", ["--target", str(filepath), "--mode", mode])


def _exec_pcap_analyze(args: dict) -> str:
    """Run PCAP network capture analysis."""
    target = args.get("target", "")
    mode = args.get("mode", "auto")

    if not target:
        return json.dumps({"error": "target .pcap file is required"})

    filepath = _sanitize_path(target)
    return _run_python_scanner("pcap_analyzer.py", ["--target", str(filepath), "--mode", mode])


def _exec_forensic_analyze(args: dict) -> str:
    """Run digital forensics analysis."""
    target = args.get("target", "")
    mode = args.get("mode", "auto")

    if not target:
        return json.dumps({"error": "target file/image path is required"})

    filepath = _sanitize_path(target)
    return _run_python_scanner("forensic_toolkit.py", ["--target", str(filepath), "--mode", mode])


def _exec_binary_analyze(args: dict) -> str:
    """Run binary reverse engineering analysis."""
    target = args.get("target", "")
    mode = args.get("mode", "auto")
    function = args.get("function", "main")

    if not target:
        return json.dumps({"error": "target binary path is required"})

    filepath = _sanitize_path(target)
    cli_args = ["--target", str(filepath), "--mode", mode]
    if mode == "disasm":
        cli_args.extend(["--function", function])

    return _run_python_scanner("disasm_analyzer.py", cli_args)


def _exec_pwn_toolkit(args: dict) -> str:
    """Run binary exploitation toolkit."""
    target = args.get("target", "")
    mode = args.get("mode", "auto")
    length = args.get("length", 200)
    find_value = args.get("find", "")

    cli_args = ["--mode", mode]
    if target:
        cli_args.extend(["--target", str(_sanitize_path(target))])
    else:
        cli_args.extend(["--target", "/dev/null"])

    if length and mode == "cyclic":
        cli_args.extend(["--length", str(int(length))])
    if find_value:
        cli_args.extend(["--find", str(find_value)])

    return _run_python_scanner("pwn_toolkit.py", cli_args)


def _exec_privesc_scan(args: dict) -> str:
    """Run privilege escalation scanner."""
    mode = args.get("mode", "auto")
    return _run_python_scanner("privesc_scanner.py", ["--target", "localhost", "--mode", mode])


def _exec_scan_llm_headers(args: dict) -> str:
    """Scan LLM provider endpoints for missing security headers and generate PoCs."""
    provider = args.get("provider", "all")
    extra_urls = args.get("extra_urls", "")
    save_pocs = args.get("save_pocs", True)
    rate_limit = args.get("rate_limit", 5)

    valid_providers = [
        "all", "openai", "anthropic", "google", "mistral", "cohere",
        "meta", "huggingface", "perplexity", "together", "fireworks", "groq",
    ]
    if provider not in valid_providers:
        return json.dumps({
            "error": f"Invalid provider: {provider}",
            "valid_providers": valid_providers,
        })

    # --target is required by parse_base_args but header_poc_generator ignores it
    # when --providers is used; pass a placeholder
    cmd_args = ["--target", "https://api.openai.com"]

    # --providers with nargs="*" — pass provider name(s) after the flag
    if provider == "all":
        cmd_args.append("--providers")  # no value = all providers
    else:
        cmd_args.extend(["--providers", provider])

    if extra_urls:
        extra_list = [u.strip() for u in extra_urls.split(",") if u.strip()]
        valid_extras = [u for u in extra_list if _is_valid_url(u)]
        if valid_extras:
            cmd_args.append("--extra-urls")
            cmd_args.extend(valid_extras)

    if save_pocs:
        poc_dir = str(PROJECT_ROOT / "reports" / "header-poc-generator")
        cmd_args.extend(["--save-pocs", poc_dir])

    if isinstance(rate_limit, int) and 1 <= rate_limit <= 50:
        cmd_args.extend(["--rate-limit", str(rate_limit)])

    cmd_args.append("--verbose")

    return _run_python_scanner("header_poc_generator.py", cmd_args)
