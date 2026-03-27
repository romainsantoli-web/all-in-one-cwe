# E2E Crypto Audit Toolkit

End-to-End Encryption Security Assessment Tool — 6 modules for auditing client-side cryptography implementations (WASM, Web Crypto API, custom protocols).

## Modules

| # | Module | Description | Detects |
|---|--------|-------------|---------|
| 1 | `wasm` | WASM Binary Analyzer | Weak algorithms, hardcoded keys, deprecated crypto in WASM |
| 2 | `keyexchange` | Key Exchange Analyzer | Weak DH/ECDH params, missing PFS, Math.random() in crypto |
| 3 | `downgrade` | Downgrade Detector | Version rollback, cipher stripping, fallback abuse |
| 4 | `iv` | IV/Key Reuse Analyzer | Nonce reuse (fatal for GCM), two-time pad, predictable IVs |
| 5 | `metadata` | Metadata Leak Analyzer | Size correlation, filename/type leakage, timing inference |
| 6 | `timing` | Timing Oracle Detector | Padding oracle, MAC timing, compression oracle (BREACH) |

## Usage

```bash
# Run all modules against a target
python cli.py --url https://target.com --all

# Run specific modules
python cli.py --url https://target.com --modules wasm,timing,iv

# Analyze local WASM binary
python cli.py --wasm-path ./libcryptobox.wasm --modules wasm

# Analyze JS sources for Web Crypto API misuse
python cli.py --js-dir ./source_maps/ --modules keyexchange

# Timing analysis with 50 rounds per test
python cli.py --url https://target.com --modules timing --rounds 50

# Docker
docker build -t e2e-crypto-audit .
docker run e2e-crypto-audit --url https://target.com --all
```

## Output

Reports are saved to `--output` directory (default `/tmp/e2e-audit/`):
- `AUDIT-REPORT.md` — Human-readable Markdown report
- `audit-report.json` — Machine-readable JSON
- Per-module JSON files

## Requirements

- Python 3.10+
- `wabt` (for `wasm2wat`): `brew install wabt` / `apt install wabt`
- Dependencies: `pip install -r requirements.txt`

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
