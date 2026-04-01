# Dashboard Architecture Map

> Référence rapide — évite de re-explorer à chaque session.

## Env (.env.local)

```
REPORTS_DIR=/Users/romain/analyse/security-all-in-one-cwe/reports
PROJECT_ROOT=/Users/romain/analyse/security-all-in-one-cwe
PYTHON_BIN=/Users/romain/analyse/.venv/bin/python3
```

## Paths clés sur disque

| Donnée         | Chemin                                                                |
| --------------- | --------------------------------------------------------------------- |
| Jobs JSON       | `$PROJECT_ROOT/reports/.jobs/<uuid>.json`                           |
| Job summaries   | `$PROJECT_ROOT/reports/.jobs/<uuid>-summary.json`                   |
| Job logs        | `$PROJECT_ROOT/reports/.jobs/<uuid>.log`                            |
| Unified reports | `$REPORTS_DIR/unified-report-*.json` (= `$PROJECT_ROOT/reports/`) |
| Tool reports    | `$PROJECT_ROOT/reports/<tool>/scan-latest.json`                     |
| Payload stats   | `$PROJECT_ROOT/reports/payload-stats.json`                          |

## next.config.mjs

```js
{ output: "standalone", serverExternalPackages: ["node-pty"] }
```

## Pages (18)

| Route            | Fichier                      | Type                                                                                      |
| ---------------- | ---------------------------- | ----------------------------------------------------------------------------------------- |
| `/`            | `app/page.tsx`             | Dashboard home                                                                            |
| `/ai`          | `app/ai/page.tsx`          | AI assistant                                                                              |
| `/autopilot`   | `app/autopilot/page.tsx`   | Autopilot mode                                                                            |
| `/compare`     | `app/compare/page.tsx`     | Compare scans                                                                             |
| `/forensics`   | `app/forensics/page.tsx`   | CTF Forensics — Crypto Analyzer, Steg Analyzer, PCAP Analyzer, Forensic Toolkit (4 tabs) |
| `/graph`       | `app/graph/page.tsx`       | CWE graph                                                                                 |
| `/launch`      | `app/launch/page.tsx`      | Trigger scans — uses `ScanLauncher` + `listJobs()`                                   |
| `/launch/[id]` | `app/launch/[id]/page.tsx` | Job detail — status, KPIs, tool results, log viewer                                      |
| `/llm`         | `app/llm/page.tsx`         | LLM analysis                                                                              |
| `/memory`      | `app/memory/page.tsx`      | Memory                                                                                    |
| `/passwords`   | `app/passwords/page.tsx`   | Vault Scanner + Wordlist Generator + Recovery Pipeline + Android ADB Bridge (4 sections)  |
| `/payloads`    | `app/payloads/page.tsx`    | Payload engine                                                                            |
| `/reversing`   | `app/reversing/page.tsx`   | CTF Reversing — Binary Analysis, Pwn Toolkit, Privesc Scanner (3 tabs)                   |
| `/scans`       | `app/scans/page.tsx`       | Scan reports list — client polling 5s via `ScansList`                                  |
| `/scans/[id]`  | `app/scans/[id]/page.tsx`  | Single scan report                                                                        |
| `/scope`       | `app/scope/page.tsx`       | Scope config                                                                              |
| `/settings`    | `app/settings/page.tsx`    | Settings                                                                                  |
| `/smart`       | `app/smart/page.tsx`       | Smart analysis                                                                            |
| `/terminals`   | `app/terminals/page.tsx`   | Terminals + AI sessions                                                                   |
| `/tools`       | `app/tools/page.tsx`       | Tool catalog                                                                              |

## API Routes (35+)

| Endpoint                                  | Fichier                                   | Méthodes        | Lib                                                                                      |
| ----------------------------------------- | ----------------------------------------- | ---------------- | ---------------------------------------------------------------------------------------- |
| `/api/scans`                            | `api/scans/route.ts`                    | GET              | `data.listScans()` → enriched objects (filename, target, date, severityCounts)        |
| `/api/scans/[id]`                       | `api/scans/[id]/route.ts`               | GET,DELETE,PATCH | `data.loadScan()`, `data.deleteScan()`, `data.renameScan()`                        |
| `/api/scans/[id]/pdf`                   | `api/scans/[id]/pdf/route.ts`           | GET              | `pdf-report.generatePDF()` — returns PDF binary                                       |
| `/api/scans/jobs`                       | `api/scans/jobs/route.ts`               | GET              | `jobs.listJobs()` — lit `$PROJECT_ROOT/reports/.jobs/*.json`                        |
| `/api/scans/jobs/[id]`                  | `api/scans/jobs/[id]/route.ts`          | GET,DELETE       | `jobs.getJob()`, `jobs.updateJob()`                                                  |
| `/api/scans/jobs/[id]/summary`          | `api/scans/jobs/[id]/summary/route.ts`  | GET              | `jobs.getJobSummary()` — lit `-summary.json`                                        |
| `/api/scans/jobs/[id]/log`              | `api/scans/jobs/[id]/log/route.ts`      | GET              | Raw `.log` file (text/plain)                                                           |
| `/api/scans/trigger`                    | `api/scans/trigger/route.ts`            | POST             | `jobs.createJob()` + `spawn(runner.py)`                                              |
| `/api/stream/[jobId]`                   | `api/stream/[jobId]/route.ts`           | GET(SSE)         | Streams job output                                                                       |
| `/api/terminals`                        | `api/terminals/route.ts`                | GET,POST         | Scan terminal listing + kill                                                             |
| `/api/terminals/[jobId]/stream`         | `api/terminals/[jobId]/stream/route.ts` | GET(SSE)         | Terminal output stream                                                                   |
| `/api/terminals/logs`                   | `api/terminals/logs/route.ts`           | GET              | Terminal log files                                                                       |
| `/api/terminals/ai-session`             | `api/terminals/ai-session/route.ts`     | GET,POST,DELETE  | `interactive-sessions`                                                                 |
| `/api/terminals/ai-session/[id]/input`  | `...input/route.ts`                     | POST             | `sendInput()`                                                                          |
| `/api/terminals/ai-session/[id]/resize` | `...resize/route.ts`                    | POST             | `resizeSession()`                                                                      |
| `/api/terminals/ai-session/[id]/stream` | `...stream/route.ts`                    | GET(SSE)         | `subscribeOutput()`                                                                    |
| `/api/tools/run`                        | `api/tools/run/route.ts`                | POST             | Run single tool                                                                          |
| `/api/tools/[name]/status`              | `api/tools/[name]/status/route.ts`      | GET              | Tool availability                                                                        |
| `/api/llm/providers`                    | `api/llm/providers/route.ts`            | GET              | LLM provider list                                                                        |
| `/api/llm/analyze`                      | `api/llm/analyze/route.ts`              | POST(SSE)        | LLM analysis stream                                                                      |
| `/api/llm/chat`                         | `api/llm/chat/route.ts`                 | POST(SSE)        | LLM chat stream                                                                          |
| `/api/llm/agent`                        | `api/llm/agent/route.ts`                | POST             | Agent execution                                                                          |
| `/api/llm/smart-analyze`                | `api/llm/smart-analyze/route.ts`        | POST             | Smart analysis                                                                           |
| `/api/config`                           | `api/config/route.ts`                   | GET              | App config                                                                               |
| `/api/settings`                         | `api/settings/route.ts`                 | GET,POST         | User settings                                                                            |
| `/api/copilot/bridge`                   | `api/copilot/bridge/route.ts`           | GET,POST         | Copilot bridge                                                                           |
| `/api/copilot/chat`                     | `api/copilot/chat/route.ts`             | POST             | Copilot chat                                                                             |
| `/api/cdp/launch`                       | `api/cdp/launch/route.ts`               | POST             | Chrome DevTools                                                                          |
| `/api/cdp/status`                       | `api/cdp/status/route.ts`               | GET              | CDP status                                                                               |
| `/api/android`                          | `api/android/route.ts`                  | GET,POST         | ADB device management + actions                                                          |
| `/api/passwords/*`                      | `api/passwords/`                        | POST             | Vault scan, extract, recover, decrypt, formats                                           |
| `/api/forensics`                        | `api/forensics/route.ts`                | POST             | CTF forensics scanners (crypto-analyzer, steg-analyzer, pcap-analyzer, forensic-toolkit) |
| `/api/reversing`                        | `api/reversing/route.ts`                | POST             | CTF reversing scanners (disasm-analyzer, pwn-toolkit, privesc-scanner)                   |
| `/api/chains/*`                         | `api/chains/`                           | GET,POST         | Chain execution engine                                                                   |
| `/api/memory/*`                         | `api/memory/`                           | GET,POST         | Session memory persistence                                                               |

## Libs (src/lib/)

| Fichier                     | Rôle                                                                                                                                 | Env vars utilisées                                  |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- |
| `jobs.ts`                 | CRUD jobs JSON + summaries dans `.jobs/` (`listJobs`, `getJob`, `createJob`, `updateJob`, `deleteJob`, `getJobSummary`) | `PROJECT_ROOT` → `$PROJECT_ROOT/reports/.jobs/` |
| `data.ts`                 | Read/delete/rename unified reports + payload stats                                                                                    | `REPORTS_DIR`, `PROJECT_ROOT`                    |
| `pdf-report.ts`           | PDF generation (jspdf + jspdf-autotable) — header, exec summary, tool breakdown, findings table                                      | —                                                   |
| `api-client.ts`           | Client-side typed fetch helpers (`getJob`, `getJobSummary`, `getJobLog`, `listJobs`, etc.)                                    | — (browser)                                         |
| `interactive-sessions.ts` | PTY sessions (node-pty/child_process)                                                                                                 | —                                                   |
| `copilot-bridge.ts`       | Copilot Pro credential injection                                                                                                      | —                                                   |
| `llm-bridge.ts`           | LLM provider abstraction                                                                                                              | `ANTHROPIC_API_KEY`, `MISTRAL_API_KEY`, etc.     |
| `tools-data.ts`           | Tool catalog + profiles (light/medium/full)                                                                                           | —                                                   |
| `types.ts`                | Shared types (ScanReport, Finding, etc.)                                                                                              | —                                                   |
| `settings.ts`             | Settings persistence                                                                                                                  | —                                                   |

## Components (23)

| Composant                   | Rôle                                                                                           |
| --------------------------- | ----------------------------------------------------------------------------------------------- |
| `Sidebar.tsx`             | Nav latérale statique — 14 items, pas de badges dynamiques                                    |
| `TerminalBubble.tsx`      | Widget flottant PixelDog + badge count (poll 3s)                                                |
| `TerminalOverlay.tsx`     | Modal overlay — tabs terminals/connect                                                         |
| `TerminalPanel.tsx`       | Affichage output terminal (SSE stream)                                                          |
| `InteractiveTerminal.tsx` | xterm.js + SSE + input/resize API                                                               |
| `PixelDog.tsx`            | Tamagotchi pixel dog animation                                                                  |
| `ScanLauncher.tsx`        | Formulaire de lancement de scan (target, profile, tools)                                        |
| `FindingsTable.tsx`       | Table de findings avec tri/filtres                                                              |
| `SeverityBadge.tsx`       | Badge coloré par sévérité                                                                   |
| `SeverityChart.tsx`       | Chart sévérités (chart.js)                                                                   |
| `CvssHistogram.tsx`       | Histogramme CVSS                                                                                |
| `CweBarChart.tsx`         | Bar chart CWE                                                                                   |
| `ToolBarChart.tsx`        | Bar chart outils                                                                                |
| `LLMChat.tsx`             | Chat LLM interactif                                                                             |
| `AskAIButton.tsx`         | Bouton "Analyze with AI"                                                                        |
| `SmartAnalyzeButton.tsx`  | Bouton smart analyze                                                                            |
| `StreamingOutput.tsx`     | Affichage streaming SSE                                                                         |
| `ExportButton.tsx`        | Export report (PDF/JSON/CSV) — PDF via API call                                                |
| `ScanActions.tsx`         | Per-report actions: download dropdown (PDF/JSON/CSV), rename inline, delete with confirm        |
| `ScansList.tsx`           | Client wrapper for Scans page — interactive list with actions (SSR data, client interactivity) |
| `QuickActions.tsx`        | Actions rapides dashboard                                                                       |
| `ToolRunner.tsx`          | Run single tool UI                                                                              |
| `ProviderTestButton.tsx`  | Test LLM provider                                                                               |

## Hooks (src/hooks/)

| Hook                | Rôle                   |
| ------------------- | ----------------------- |
| `useJobStatus.ts` | Poll job status by ID   |
| `useSSE.ts`       | Generic SSE stream hook |

## Data Flow

```
ScanLauncher (component)
  → POST /api/scans/trigger
    → jobs.createJob() → writes .jobs/<id>.json
    → spawn(runner.py --target URL --profile P --job-id ID)
    → runner.py runs tools → writes reports/<tool>/scan-latest.json
    → runner.py writes .jobs/<id>-summary.json (per-tool results + total_findings)
    → runner.py writes .jobs/<id>.log (stdout/stderr)
    → runner.py calls merge-reports.py --scan-date D --target URL
      → auto-discovers ALL reports/<tool>/ directories
      → uses TOOL_PARSERS for known tools, parse_python_scanner as fallback
      → writes unified-report-<date>.json with target field
    → child.on("exit") → reads summary for findings count → updateJob(status: completed)

Launch page (/launch)
  → listJobs() → GET /api/scans/jobs → jobs.listJobs() → reads .jobs/*.json
  → click job → navigates to /launch/<jobId>

Job detail page (/launch/[id]) — client component, polls 3s while running
  → getJob(id)        → GET /api/scans/jobs/<id>        → status, progress, findings
  → getJobSummary(id) → GET /api/scans/jobs/<id>/summary → per-tool results table
  → getJobLog(id)     → GET /api/scans/jobs/<id>/log     → raw log text (lazy)
  → getToolFindings() → GET /api/scans/jobs/<id>/findings/<tool> → expandable per-tool findings

Scans page (/scans — client with 5s polling)
  → GET /api/scans → data.listScans() → enriched objects {filename, target, date, severityCounts}
  → ScansList component renders with ScanActions (download PDF/JSON/CSV, rename, delete)

Terminals page (client)
  → GET /api/terminals (scan process list)
  → GET /api/terminals/ai-session (interactive sessions)
```

## Dépendances npm

**Prod:** next@15, react@19, react-dom@19, chart.js@4, react-chartjs-2@5, @xterm/xterm@6, @xterm/addon-fit@0.11, node-pty@1.1, jspdf@2, jspdf-autotable@5
**Dev:** typescript@5.6, tailwindcss@4, eslint@9, postcss@8

## Lancement du dev server

```bash
# IMPORTANT : toujours se placer dans le dossier dashboard/ AVANT de lancer
cd /Users/romain/analyse/security-all-in-one-cwe/dashboard

# Pré-requis une seule fois après npm install
chmod +x node_modules/node-pty/prebuilds/darwin-arm64/spawn-helper

# Nettoyage cache si build cassé
rm -rf .next

# Lancement
npx next dev -p 3000
```

**Pourquoi cd est obligatoire :**

- Next.js cherche `app/` ou `pages/` dans le **cwd** du process, pas relativement au `package.json`
- Le dossier `app/` est sous `src/app/` (configuré via `tsconfig.json` paths `@/* → ./src/*`)
- Si lancé depuis le workspace root (`/Users/romain/analyse`), Next.js ne trouvera pas `app/` → erreur `Couldn't find any pages or app directory`

**Agents / Copilot :** les terminaux background démarrent toujours depuis le workspace root.
Pour lancer correctement, utiliser un terminal non-background déjà `cd` dans `dashboard/`,
ou bien chaîner dans la même commande : `cd /Users/romain/analyse/security-all-in-one-cwe/dashboard && npx next dev`

## Notes importantes

- **REPORTS_DIR** pointe vers le même dossier que `$PROJECT_ROOT/reports/` — pas de sous-dossier `unified/`
- **Jobs** : persistés en JSON dans `$PROJECT_ROOT/reports/.jobs/`
- **Scan reports** : écrits par `runner.py` dans `$REPORTS_DIR/unified-report-<date>.json`
- **Job summaries** : écrits par `runner.py` dans `.jobs/<id>-summary.json` — contient résultats per-tool (tool, status, elapsed_s, findings)
- **Job logs** : écrits par `runner.py` dans `.jobs/<id>.log` — stdout/stderr brut
- **listJobs()** : filtre les `-summary.json` via validation schema (id + status + createdAt requis)
- **Sidebar** : 100% statique, pas de badges dynamiques
- **Polling** : TerminalBubble (3s), Launch page (5s), Job detail page (3s while running), Scans page (5s), Terminals page (3s)
- **Findings count** : `trigger/route.ts` reads runner's `-summary.json` for accurate `total_findings` (fallback: `countAllFindings()`)
- **Unified report target** : `runner.py` passes `--target` to `merge-reports.py` → stored in unified report JSON → displayed in Scans page
- **merge-reports.py** : auto-discovers all `reports/<tool>/` directories (not limited to `TOOL_PARSERS`); uses `parse_python_scanner` as fallback parser
- **React keys** : `FindingsTable` uses `${f.id}-${i}` (index-suffixed) to avoid duplicates when tools share CWE IDs

## Python Scripts

| Script                       | Rôle                                                                     |
| ---------------------------- | ------------------------------------------------------------------------- |
| `runner.py`                | Scan orchestrator — runs tools, writes summaries, calls merge-reports.py |
| `scripts/merge-reports.py` | Merges per-tool reports into unified JSON (auto-discovers 75+ tool dirs)  |
| `llm/cli.py`               | CLI for LLM analysis                                                      |

## LLM Agent Tools (33) — `llm/agent_tools.py`

Tous les 6 providers (Claude, GPT, Copilot, Copilot-Pro, Mistral, Gemini) reçoivent les 33 tools via auto-injection dans `cli.py → provider.chat(tools=AGENT_TOOLS)`.

| Groupe            | Tools                                                                                                    | Description                                                                 |
| ----------------- | -------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| Orchestration     | `run_scan`, `list_tools`, `list_findings`, `update_plan`                                         | Lancement scanners, découverte outils, findings, planning                  |
| File I/O          | `read_file`, `write_file`, `list_dir`, `grep_search`, `file_search`                            | Navigation et manipulation fichiers                                         |
| Network           | `fetch_webpage`, `browse_page`, `cdp_exec`                                                         | HTTP, rendu JS, Chrome DevTools Protocol                                    |
| Reporting         | `generate_report`                                                                                      | Rapports markdown + bug bounty platforms (6 formats)                        |
| Shell             | `shell_exec`                                                                                           | Exécution commandes (120s timeout, patterns bloqués)                      |
| Workspace         | `workspace_write`, `workspace_read`, `workspace_list`                                              | Workspace isolé par conversation                                           |
| Password Recovery | `vault_scan`, `vault_extract`, `password_recover`, `password_decrypt`, `list_recovery_formats` | 23 formats chiffrés, scan + extraction + cracking + déchiffrement         |
| Android ADB       | `android_adb`, `android_wifi_capture`, `android_file_transfer`, `android_shell`                  | Device management, WiFi capture, file transfer, shell                       |
| CTF Forensics     | `crypto_analyze`, `steg_analyze`, `pcap_analyze`, `forensic_analyze`                             | Hash ID, encoding chains, steg detection, PCAP forensics, digital forensics |
| CTF Reversing     | `binary_analyze`, `pwn_toolkit`, `privesc_scan`                                                    | Checksec, disasm, ROP gadgets, shellcodes, Linux privesc                    |

## Python Scanners (35) — `tools/python-scanners/`

| Scanner                         | Cible                                                                                   |
| ------------------------------- | --------------------------------------------------------------------------------------- |
| `idor_scanner.py`             | IDOR (CWE-639)                                                                          |
| `auth_bypass.py`              | Auth bypass (CWE-287/284/915)                                                           |
| `user_enum.py`                | User enumeration (CWE-203/204)                                                          |
| `xss_scanner.py`              | XSS + SSTI + CSP (CWE-79/693/1336)                                                      |
| `ssrf_scanner.py`             | SSRF (CWE-918)                                                                          |
| `api_discovery.py`            | API endpoints via JS bundles (CWE-200/540)                                              |
| `secret_leak.py`              | Secret/token leakage (CWE-312/540/615)                                                  |
| `cache_deception.py`          | Web cache deception (CWE-524)                                                           |
| `websocket_scanner.py`        | WebSocket security (CWE-284)                                                            |
| `slowloris_check.py`          | DoS slowloris (CWE-400)                                                                 |
| `waf_bypass.py`               | WAF evasion (CWE-178)                                                                   |
| `source_map_scanner.py`       | Source map exposure (CWE-215)                                                           |
| `hidden_endpoint_scanner.py`  | Hidden endpoint discovery (CWE-215)                                                     |
| `hateoas_fuzzer.py`           | HATEOAS/REST fuzzing (CWE-639)                                                          |
| `coupon_promo_fuzzer.py`      | Business logic (CWE-639)                                                                |
| `response_pii_detector.py`    | PII in responses (CWE-200)                                                              |
| `header_classifier.py`        | Security header analysis (CWE-200)                                                      |
| `timing_oracle.py`            | Timing attacks (CWE-208)                                                                |
| `oauth_flow_scanner.py`       | OAuth flow (CWE-601)                                                                    |
| `redirect_cors.py`            | Open redirect + CORS (CWE-601/942)                                                      |
| `oidc_audit.py`               | OIDC/OAuth audit (CWE-200/287/522)                                                      |
| `bypass_403.py`               | 403 bypass (CWE-284)                                                                    |
| `notif_inject.py`             | Notification injection (CWE-74/79)                                                      |
| `cdp_token_extractor.py`      | CDP token extraction (CWE-347)                                                          |
| `cdp_checkout_interceptor.py` | CDP checkout interception (CWE-915)                                                     |
| `cdp_credential_scanner.py`   | CDP credential scanning (CWE-798)                                                       |
| `smart_wordlist.py`           | Smart wordlist generation                                                               |
| `osint_enricher.py`           | OSINT enrichment                                                                        |
| `crypto_analyzer.py`          | Cryptanalysis — hash ID, encoding chains, frequency, Caesar, XOR, RSA (CWE-327/310)    |
| `steg_analyzer.py`            | Steganography — magic bytes, strings, appended data, embedded files, entropy (CWE-532) |
| `pcap_analyzer.py`            | PCAP forensics — protocol stats, credentials, DNS exfil, HTTP extraction (CWE-319)     |
| `forensic_toolkit.py`         | Digital forensics — metadata, timestomping, carving, Volatility (CWE-532)              |
| `disasm_analyzer.py`          | Binary analysis — checksec, ELF/PE, functions, disasm, format strings (CWE-693)        |
| `pwn_toolkit.py`              | Exploitation — cyclic patterns, ROP gadgets, one_gadget, shellcodes (CWE-119)          |
| `privesc_scanner.py`          | Privilege escalation — SUID/GTFOBins, caps, cron, sudo, container escape (CWE-250/269) |

## Couverture CTF — État actuel

| Catégorie          | Score  | Outils                                                                                                   |
| ------------------- | ------ | -------------------------------------------------------------------------------------------------------- |
| Web Exploitation    | ✅ 95% | 28+ web scanners, XSS/SSRF/SQLi/IDOR/CSRF, CDP bridge                                                    |
| Cryptography        | ✅ 85% | `crypto_analyzer.py` — hash ID (50+ formats), encoding chains, Caesar, XOR, RSA                       |
| Forensics           | ✅ 80% | `steg_analyzer.py` + `pcap_analyzer.py` + `forensic_toolkit.py` — steg, PCAP, carving, Volatility |
| Reverse Engineering | ✅ 75% | `disasm_analyzer.py` — checksec, ELF/PE, disasm, format strings, r2/objdump                           |
| Pwn                 | ✅ 80% | `pwn_toolkit.py` — cyclic patterns, ROP gadgets, one_gadget, shellcodes                               |
| Priv Escalation     | ✅ 85% | `privesc_scanner.py` — SUID/GTFOBins (40+), caps, cron, sudo, container escape, kernel                |

Total CTF coverage: **~83%** (was 38%). Voir `CTF-GAP-ANALYSIS.md` pour les gaps restants.
