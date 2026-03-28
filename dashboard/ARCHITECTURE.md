# Dashboard Architecture Map

> Référence rapide — évite de re-explorer à chaque session.

## Env (.env.local)

```
REPORTS_DIR=/Users/romain/analyse/security-all-in-one-cwe/reports
PROJECT_ROOT=/Users/romain/analyse/security-all-in-one-cwe
PYTHON_BIN=/Users/romain/analyse/.venv/bin/python3
```

## Paths clés sur disque

| Donnée | Chemin |
|--------|--------|
| Jobs JSON | `$PROJECT_ROOT/reports/.jobs/<uuid>.json` |
| Job summaries | `$PROJECT_ROOT/reports/.jobs/<uuid>-summary.json` |
| Job logs | `$PROJECT_ROOT/reports/.jobs/<uuid>.log` |
| Unified reports | `$REPORTS_DIR/unified-report-*.json` (= `$PROJECT_ROOT/reports/`) |
| Tool reports | `$PROJECT_ROOT/reports/<tool>/scan-latest.json` |
| Payload stats | `$PROJECT_ROOT/reports/payload-stats.json` |

## next.config.mjs

```js
{ output: "standalone", serverExternalPackages: ["node-pty"] }
```

## Pages (15)

| Route | Fichier | Type |
|-------|---------|------|
| `/` | `app/page.tsx` | Dashboard home |
| `/ai` | `app/ai/page.tsx` | AI assistant |
| `/compare` | `app/compare/page.tsx` | Compare scans |
| `/graph` | `app/graph/page.tsx` | CWE graph |
| `/launch` | `app/launch/page.tsx` | Trigger scans — uses `ScanLauncher` + `listJobs()` |
| `/launch/[id]` | `app/launch/[id]/page.tsx` | Job detail — status, KPIs, tool results, log viewer |
| `/llm` | `app/llm/page.tsx` | LLM analysis |
| `/memory` | `app/memory/page.tsx` | Memory |
| `/payloads` | `app/payloads/page.tsx` | Payload engine |
| `/scans` | `app/scans/page.tsx` | Scan reports list — client polling 5s via `ScansList` |
| `/scans/[id]` | `app/scans/[id]/page.tsx` | Single scan report |
| `/scope` | `app/scope/page.tsx` | Scope config |
| `/settings` | `app/settings/page.tsx` | Settings |
| `/smart` | `app/smart/page.tsx` | Smart analysis |
| `/terminals` | `app/terminals/page.tsx` | Terminals + AI sessions |
| `/tools` | `app/tools/page.tsx` | Tool catalog |

## API Routes (29)

| Endpoint | Fichier | Méthodes | Lib |
|----------|---------|----------|-----|
| `/api/scans` | `api/scans/route.ts` | GET | `data.listScans()` → enriched objects (filename, target, date, severityCounts) |
| `/api/scans/[id]` | `api/scans/[id]/route.ts` | GET,DELETE,PATCH | `data.loadScan()`, `data.deleteScan()`, `data.renameScan()` |
| `/api/scans/[id]/pdf` | `api/scans/[id]/pdf/route.ts` | GET | `pdf-report.generatePDF()` — returns PDF binary |
| `/api/scans/jobs` | `api/scans/jobs/route.ts` | GET | `jobs.listJobs()` — lit `$PROJECT_ROOT/reports/.jobs/*.json` |
| `/api/scans/jobs/[id]` | `api/scans/jobs/[id]/route.ts` | GET,DELETE | `jobs.getJob()`, `jobs.updateJob()` |
| `/api/scans/jobs/[id]/summary` | `api/scans/jobs/[id]/summary/route.ts` | GET | `jobs.getJobSummary()` — lit `-summary.json` |
| `/api/scans/jobs/[id]/log` | `api/scans/jobs/[id]/log/route.ts` | GET | Raw `.log` file (text/plain) |
| `/api/scans/trigger` | `api/scans/trigger/route.ts` | POST | `jobs.createJob()` + `spawn(runner.py)` |
| `/api/stream/[jobId]` | `api/stream/[jobId]/route.ts` | GET(SSE) | Streams job output |
| `/api/terminals` | `api/terminals/route.ts` | GET,POST | Scan terminal listing + kill |
| `/api/terminals/[jobId]/stream` | `api/terminals/[jobId]/stream/route.ts` | GET(SSE) | Terminal output stream |
| `/api/terminals/logs` | `api/terminals/logs/route.ts` | GET | Terminal log files |
| `/api/terminals/ai-session` | `api/terminals/ai-session/route.ts` | GET,POST,DELETE | `interactive-sessions` |
| `/api/terminals/ai-session/[id]/input` | `...input/route.ts` | POST | `sendInput()` |
| `/api/terminals/ai-session/[id]/resize` | `...resize/route.ts` | POST | `resizeSession()` |
| `/api/terminals/ai-session/[id]/stream` | `...stream/route.ts` | GET(SSE) | `subscribeOutput()` |
| `/api/tools/run` | `api/tools/run/route.ts` | POST | Run single tool |
| `/api/tools/[name]/status` | `api/tools/[name]/status/route.ts` | GET | Tool availability |
| `/api/llm/providers` | `api/llm/providers/route.ts` | GET | LLM provider list |
| `/api/llm/analyze` | `api/llm/analyze/route.ts` | POST(SSE) | LLM analysis stream |
| `/api/llm/chat` | `api/llm/chat/route.ts` | POST(SSE) | LLM chat stream |
| `/api/llm/agent` | `api/llm/agent/route.ts` | POST | Agent execution |
| `/api/llm/smart-analyze` | `api/llm/smart-analyze/route.ts` | POST | Smart analysis |
| `/api/config` | `api/config/route.ts` | GET | App config |
| `/api/settings` | `api/settings/route.ts` | GET,POST | User settings |
| `/api/copilot/bridge` | `api/copilot/bridge/route.ts` | GET,POST | Copilot bridge |
| `/api/copilot/chat` | `api/copilot/chat/route.ts` | POST | Copilot chat |
| `/api/cdp/launch` | `api/cdp/launch/route.ts` | POST | Chrome DevTools |
| `/api/cdp/status` | `api/cdp/status/route.ts` | GET | CDP status |

## Libs (src/lib/)

| Fichier | Rôle | Env vars utilisées |
|---------|------|--------------------|
| `jobs.ts` | CRUD jobs JSON + summaries dans `.jobs/` (`listJobs`, `getJob`, `createJob`, `updateJob`, `deleteJob`, `getJobSummary`) | `PROJECT_ROOT` → `$PROJECT_ROOT/reports/.jobs/` |
| `data.ts` | Read/delete/rename unified reports + payload stats | `REPORTS_DIR`, `PROJECT_ROOT` |
| `pdf-report.ts` | PDF generation (jspdf + jspdf-autotable) — header, exec summary, tool breakdown, findings table | — |
| `api-client.ts` | Client-side typed fetch helpers (`getJob`, `getJobSummary`, `getJobLog`, `listJobs`, etc.) | — (browser) |
| `interactive-sessions.ts` | PTY sessions (node-pty/child_process) | — |
| `copilot-bridge.ts` | Copilot Pro credential injection | — |
| `llm-bridge.ts` | LLM provider abstraction | `ANTHROPIC_API_KEY`, `MISTRAL_API_KEY`, etc. |
| `tools-data.ts` | Tool catalog + profiles (light/medium/full) | — |
| `types.ts` | Shared types (ScanReport, Finding, etc.) | — |
| `settings.ts` | Settings persistence | — |

## Components (23)

| Composant | Rôle |
|-----------|------|
| `Sidebar.tsx` | Nav latérale statique — 14 items, pas de badges dynamiques |
| `TerminalBubble.tsx` | Widget flottant PixelDog + badge count (poll 3s) |
| `TerminalOverlay.tsx` | Modal overlay — tabs terminals/connect |
| `TerminalPanel.tsx` | Affichage output terminal (SSE stream) |
| `InteractiveTerminal.tsx` | xterm.js + SSE + input/resize API |
| `PixelDog.tsx` | Tamagotchi pixel dog animation |
| `ScanLauncher.tsx` | Formulaire de lancement de scan (target, profile, tools) |
| `FindingsTable.tsx` | Table de findings avec tri/filtres |
| `SeverityBadge.tsx` | Badge coloré par sévérité |
| `SeverityChart.tsx` | Chart sévérités (chart.js) |
| `CvssHistogram.tsx` | Histogramme CVSS |
| `CweBarChart.tsx` | Bar chart CWE |
| `ToolBarChart.tsx` | Bar chart outils |
| `LLMChat.tsx` | Chat LLM interactif |
| `AskAIButton.tsx` | Bouton "Analyze with AI" |
| `SmartAnalyzeButton.tsx` | Bouton smart analyze |
| `StreamingOutput.tsx` | Affichage streaming SSE |
| `ExportButton.tsx` | Export report (PDF/JSON/CSV) — PDF via API call |
| `ScanActions.tsx` | Per-report actions: download dropdown (PDF/JSON/CSV), rename inline, delete with confirm |
| `ScansList.tsx` | Client wrapper for Scans page — interactive list with actions (SSR data, client interactivity) |
| `QuickActions.tsx` | Actions rapides dashboard |
| `ToolRunner.tsx` | Run single tool UI |
| `ProviderTestButton.tsx` | Test LLM provider |

## Hooks (src/hooks/)

| Hook | Rôle |
|------|------|
| `useJobStatus.ts` | Poll job status by ID |
| `useSSE.ts` | Generic SSE stream hook |

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

## Notes importantes

- **node-pty spawn-helper** : après `npm install`, faire `chmod +x node_modules/node-pty/prebuilds/darwin-arm64/spawn-helper`
- **Dev server** : doit être lancé depuis `/security-all-in-one-cwe/dashboard/` (sinon Next.js ne trouve pas `app/`)
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

| Script | Rôle |
|--------|------|
| `runner.py` | Scan orchestrator — runs tools, writes summaries, calls merge-reports.py |
| `scripts/merge-reports.py` | Merges per-tool reports into unified JSON (auto-discovers 75+ tool dirs) |
| `llm/cli.py` | CLI for LLM analysis |
