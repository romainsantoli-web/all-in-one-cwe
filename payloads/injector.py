"""PayloadInjector — Generate scanner-specific payload files.

Maps PayloadEngine output to files consumable by each scanner:
- nuclei  → custom YAML template with payloads list
- ffuf    → wordlist TXT (one payload per line)
- dalfox  → blind-params file
- sqlmap  → tamper payloads TXT
- xss-scanner / ssrf-scanner / auth-bypass → additional payloads TXT

Scanners pick up files from reports/payloads/<scanner>/ at runtime.
NO existing scanner code is modified — this is a complement layer.

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from payloads import PayloadSet

log = logging.getLogger("payloads.injector")

# Default output directory
DEFAULT_OUTPUT_DIR = Path("reports/payloads")

# ---------------------------------------------------------------------------
# Scanner-specific format generators
# ---------------------------------------------------------------------------

# Mapping: scanner name → format function name
_SCANNER_FORMATS = {
    "nuclei": "_fmt_nuclei",
    "ffuf": "_fmt_wordlist",
    "feroxbuster": "_fmt_wordlist",
    "dalfox": "_fmt_dalfox",
    "sqlmap": "_fmt_sqlmap",
    "xss-scanner": "_fmt_wordlist",
    "ssrf-scanner": "_fmt_wordlist",
    "auth-bypass": "_fmt_wordlist",
    "idor-scanner": "_fmt_wordlist",
    "command-injection": "_fmt_wordlist",
    "directory-traversal": "_fmt_wordlist",
    "open-redirect": "_fmt_wordlist",
    "csrf-scanner": "_fmt_wordlist",
    "nosql-injection": "_fmt_wordlist",
    "ldap-injection": "_fmt_wordlist",
    "upload-scanner": "_fmt_wordlist",
    "smuggler": "_fmt_wordlist",
    "cache-deception": "_fmt_wordlist",
    "jwt-tool": "_fmt_wordlist",
    "ppmap": "_fmt_wordlist",
    "generic": "_fmt_wordlist",
}


class PayloadInjector:
    """Generate scanner-specific payload files from PayloadSets.

    Usage:
        injector = PayloadInjector(output_dir=Path("reports/payloads"))
        files = injector.inject(scanner_payloads)
        # scanner_payloads: dict[scanner_name, list[PayloadSet]]
    """

    def __init__(
        self,
        output_dir: Path | None = None,
        target: str = "",
    ) -> None:
        self._output_dir = output_dir or DEFAULT_OUTPUT_DIR
        self._target = target

    def inject(
        self,
        scanner_payloads: dict[str, list[PayloadSet]],
    ) -> dict[str, list[Path]]:
        """Generate payload files for all scanners.

        Args:
            scanner_payloads: Mapping of scanner name → list of PayloadSets.

        Returns:
            Mapping of scanner name → list of generated file paths.
        """
        generated: dict[str, list[Path]] = {}

        for scanner, payload_sets in scanner_payloads.items():
            if not payload_sets:
                continue

            # Flatten payloads from all sets
            payloads = []
            for ps in payload_sets:
                payloads.extend(ps.payloads)

            # Deduplicate while preserving order
            payloads = list(dict.fromkeys(payloads))

            if not payloads:
                continue

            # Get the formatter for this scanner
            fmt_name = _SCANNER_FORMATS.get(scanner, "_fmt_wordlist")
            fmt_func = _FORMATTERS[fmt_name]

            scanner_dir = self._output_dir / scanner
            scanner_dir.mkdir(parents=True, exist_ok=True)

            files = fmt_func(
                payloads=payloads,
                scanner=scanner,
                output_dir=scanner_dir,
                target=self._target,
                payload_sets=payload_sets,
            )
            generated[scanner] = files

            log.info(
                "Injected %d payloads for %s → %d file(s)",
                len(payloads),
                scanner,
                len(files),
            )

        return generated

    def inject_from_strings(
        self,
        scanner_payloads: dict[str, list[str]],
    ) -> dict[str, list[Path]]:
        """Generate payload files from raw strings (as produced by payload_task).

        Convenience wrapper that wraps string lists into PayloadSets.
        """
        from payloads import RiskLevel, classify_risk

        wrapped: dict[str, list[PayloadSet]] = {}
        for scanner, lines in scanner_payloads.items():
            if not lines:
                continue
            max_risk = max(
                (classify_risk(p) for p in lines),
                default=RiskLevel.LOW,
                key=lambda r: list(RiskLevel).index(r),
            )
            wrapped[scanner] = [
                PayloadSet(
                    name=f"{scanner}-enriched",
                    category=scanner,
                    cwe="",
                    source="engine",
                    risk_level=max_risk,
                    payloads=lines,
                    file_path="",
                    tags=["injected"],
                )
            ]
        return self.inject(wrapped)


# ---------------------------------------------------------------------------
# Format functions — each returns list[Path] of generated files
# ---------------------------------------------------------------------------


def _fmt_wordlist(
    payloads: list[str],
    scanner: str,
    output_dir: Path,
    **_kwargs: Any,
) -> list[Path]:
    """Plain TXT wordlist — one payload per line.

    Works for: ffuf, feroxbuster, xss-scanner, ssrf-scanner, and most others.
    """
    out = output_dir / "payloads.txt"
    out.write_text("\n".join(payloads) + "\n")
    return [out]


def _fmt_nuclei(
    payloads: list[str],
    scanner: str,
    output_dir: Path,
    target: str = "",
    payload_sets: list[PayloadSet] | None = None,
    **_kwargs: Any,
) -> list[Path]:
    """Nuclei custom template with payload list.

    Generates a fuzzing template that feeds payloads into nuclei's
    {{payload}} variable for HTTP request injection.
    """
    # Determine category from the first payload set
    category = "payload-injection"
    cwe = ""
    if payload_sets:
        category = payload_sets[0].category.lower().replace(" ", "-") or category
        cwe = payload_sets[0].cwe or ""

    # Write the payload wordlist
    wordlist_path = output_dir / "payloads.txt"
    wordlist_path.write_text("\n".join(payloads) + "\n")

    # Generate a nuclei template that references the wordlist
    template = f"""id: patt-{category}

info:
  name: "PATT {category} payloads"
  author: PayloadEngine
  severity: info
  description: "Auto-generated from PayloadsAllTheThings — {len(payloads)} payloads"
  tags: patt,{category}{f",{cwe.lower()}" if cwe else ""}

http:
  - raw:
      - |
        GET /{{{{path}}}} HTTP/1.1
        Host: {{{{Hostname}}}}

    payloads:
      path: {wordlist_path.name}

    attack: sniper

    matchers-condition: or
    matchers:
      - type: status
        status:
          - 200
          - 302
          - 500

      - type: word
        words:
          - "error"
          - "exception"
          - "syntax"
        condition: or
"""
    template_path = output_dir / f"patt-{category}.yaml"
    template_path.write_text(template)

    return [wordlist_path, template_path]


def _fmt_dalfox(
    payloads: list[str],
    scanner: str,
    output_dir: Path,
    **_kwargs: Any,
) -> list[Path]:
    """Dalfox blind XSS payload file.

    Dalfox accepts a custom payload file via --custom-payload flag.
    """
    out = output_dir / "custom-payloads.txt"
    out.write_text("\n".join(payloads) + "\n")
    return [out]


def _fmt_sqlmap(
    payloads: list[str],
    scanner: str,
    output_dir: Path,
    **_kwargs: Any,
) -> list[Path]:
    """SQLMap additional payloads.

    Write payloads as a TXT file that can be used with
    sqlmap's --prefix/--suffix or loaded as test payloads.
    Also generates a simple tamper script for custom injection points.
    """
    files: list[Path] = []

    # 1. Plain wordlist
    wordlist = output_dir / "payloads.txt"
    wordlist.write_text("\n".join(payloads) + "\n")
    files.append(wordlist)

    # 2. Tamper script that wraps payloads in comment-style obfuscation
    tamper = output_dir / "patt_tamper.py"
    tamper.write_text(
        '"""PayloadEngine tamper script for sqlmap.\n\n'
        "Auto-generated — adds PATT-sourced payloads as alternatives.\n"
        '⚠️ Contenu généré par IA — validation humaine requise avant utilisation.\n"""\n\n'
        "import random\n\n"
        "# PATT payloads loaded at import time\n"
        f"_PATT_PAYLOADS = {payloads[:50]!r}\n\n\n"
        "def tamper(payload, **kwargs):\n"
        '    """Randomly inject a PATT payload variant."""\n'
        "    if random.random() < 0.3 and _PATT_PAYLOADS:\n"
        "        return random.choice(_PATT_PAYLOADS)\n"
        "    return payload\n"
    )
    files.append(tamper)

    return files


# Registry of format functions
_FORMATTERS: dict[str, Any] = {
    "_fmt_wordlist": _fmt_wordlist,
    "_fmt_nuclei": _fmt_nuclei,
    "_fmt_dalfox": _fmt_dalfox,
    "_fmt_sqlmap": _fmt_sqlmap,
}
