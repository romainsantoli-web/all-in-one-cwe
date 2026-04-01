# 📋 Restant à Faire — security-all-in-one-cwe

> ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
>
> Dernière mise à jour : 2026-04-01
> Généré par analyse exhaustive : audit sécurité (29 findings) + gap analysis + recherche SOTA

---

## Légende

| Icône | Signification |
|-------|---------------|
| 🔴 | CRITICAL — à traiter immédiatement |
| 🟠 | HIGH — à traiter cette semaine |
| 🟡 | MEDIUM — à planifier ce sprint |
| 🔵 | LOW — backlog |
| ⭐ | SOTA — nouvelle intégration recommandée |

---

## 1. SÉCURITÉ — Vulnérabilités confirmées

### 🔴 CRITICAL (4)

- [ ] **SEC-C1** — Retirer le mount Docker socket (`/var/run/docker.sock`) sur `trivy-image`, `dockle`, `prefect-worker`
  - Risque : escape conteneur → accès root sur l'hôte
  - Fix : utiliser Trivy en mode `--server`, DinD pour les builds, Podman socket pour Dockle
  - Fichier : `docker-compose.yml`

- [ ] **SEC-C2** — Supprimer les credentials par défaut DefectDojo (`changeme`)
  - Risque : accès DB non autorisé en cas de deployment sans `.env`
  - Fix : retirer les valeurs par défaut, ajouter un check au démarrage qui fail si secrets = default
  - Fichier : `docker-compose.yml` (lignes ~850-860)

- [ ] **SEC-C3** — Ajouter une authentification sur TOUTES les routes API du Dashboard
  - Risque : n'importe qui sur le réseau peut lancer des scans, tuer des process, accéder aux findings
  - Fix : implémenter NextAuth.js (session + CSRF), middleware `middleware.ts`
  - Fichiers : `dashboard/src/app/api/*/route.ts`, `dashboard/src/middleware.ts` (à créer)

- [ ] **SEC-C4** — Corriger l'injection de commande ADB dans la route Android capture
  - Risque : RCE sur le device Android via interpolation dans `su -c`
  - Fix : utiliser `execFile` avec tableau d'arguments, jamais de concaténation shell
  - Fichier : `dashboard/src/app/api/android/capture/route.ts`

### 🟠 HIGH (12)

- [ ] **SEC-H1** — Pinner toutes les images Docker par digest SHA256 (35+ images en `:latest`)
  - Fix : `image: projectdiscovery/nuclei@sha256:<hash>` + vérif Cosign
  - Fichier : `docker-compose.yml`

- [ ] **SEC-H2** — Binder tous les ports sur `127.0.0.1` au lieu de `0.0.0.0`
  - Services exposés : zap-gui (8080/8090), prefect-server (4200), dashboard (3000), mitmproxy
  - Fix : `ports: ['127.0.0.1:3000:3000']`

- [ ] **SEC-H3** — Étendre le sandbox override à tous les services (25+ manquants)
  - Services manquants : waf-bypass, commix, wapiti, hydra, brute-forcer, osint-enricher, etc.
  - Fix : ajouter `<<: *sandbox` + capabilities spécifiques si nécessaire (NET_RAW pour masscan/nmap)
  - Fichier : `docker-compose.override.yml`

- [ ] **SEC-H4** — Ajouter des limites de ressources (`mem_limit`, `cpus`, `pids_limit`) sur tous les services
  - Risque : DoS par scanner runaway (feroxbuster deep recursion, SQLMap heavy crawl)
  - Fix : `deploy.resources.limits: { memory: 2g, cpus: '1.0' }` + `pids_limit: 100`

- [ ] **SEC-H5** — Ajouter des healthchecks sur tous les services long-running
  - Fix : `healthcheck: { test: ['CMD', 'curl', '-f', 'http://localhost:<port>/health'] }`

- [ ] **SEC-H6** — Valider `$AUTH_FILE` dans `runner.sh` avant `source`
  - Risque : exécution de code arbitraire via fichier auth malveillant
  - Fix : `grep -qvP '^[A-Z_]+=.+$' "$AUTH_FILE" && error 'Invalid auth file'`
  - Fichier : `runner.sh`

- [ ] **SEC-H7** — Remplacer `globals()[]` par dispatch dict explicite dans `merge-reports.py`
  - Fix : `PARSERS = {'nuclei': parse_nuclei, 'zap': parse_zap, ...}`
  - Fichier : `scripts/merge-reports.py`

- [ ] **SEC-H8** — Ajouter protection CSRF sur toutes les routes POST du Dashboard
  - Fix : SameSite=Strict cookies + token CSRF + vérification header Origin

- [ ] **SEC-H9** — Sécuriser la variable CI `make scan-${{ env.PROFILE }}`
  - Fix : quoter la variable `make "scan-${PROFILE}"`, valider contre allowlist
  - Fichier : `.github/workflows/security-scan.yml`

- [ ] **SEC-H10** — Protéger `node-pty` derrière authentification forte
  - Fix : retirer de la production ou gater derrière API key + IP whitelist
  - Fichiers : `dashboard/package.json`, routes terminaux

- [ ] **SEC-H11** — Mettre `scanner-net` en `internal: true`
  - Fix : créer un réseau egress séparé avec proxy pour les outils qui ont besoin d'internet
  - Fichier : `docker-compose.override.yml`

- [ ] **SEC-H12** — Pinner les repos Git clonés dans les Dockerfiles inline (15+ repos)
  - Fix : `git clone --branch v1.2.3 <repo> && git verify-commit HEAD`

### 🟡 MEDIUM (11)

- [ ] **SEC-M1** — Valider path traversal dans `lib.py load_config()`
  - Fix : `assert Path(config_path).resolve().is_relative_to(ALLOWED_DIR)`
  - Fichier : `tools/python-scanners/lib.py`

- [ ] **SEC-M2** — Remplacer `sys.path.insert` par des imports de package propres
  - Fichiers : `idor_scanner.py`, `auth_bypass.py`, `cdp_token_extractor.py`

- [ ] **SEC-M3** — Ajouter rate limiting sur les endpoints API Dashboard
  - Fix : middleware `next-rate-limit`, 60 req/min par IP

- [ ] **SEC-M4** — Sécuriser la connexion CDP (Chrome DevTools Protocol)
  - Fix : `--remote-debugging-pipe` ou token auth + bind 127.0.0.1

- [ ] **SEC-M5** — Pinner les deps pip par hash + pinner les GitHub Actions par SHA
  - Fix : `pip install --require-hashes`, `uses: actions/checkout@<sha256>`

- [ ] **SEC-M6** — Ajouter SAST/DAST sur le propre codebase dans le CI
  - ✅ Semgrep, Gitleaks, TruffleHog déjà dans docker-compose mais PAS dans le CI
  - Fix : ajouter Semgrep, CodeQL, Gitleaks, Trivy, npm audit comme steps CI (GitHub Actions)

- [ ] **SEC-M7** — Valider path traversal dans `merge-reports.py --output`
  - Fix : `assert Path(args.output).resolve().is_relative_to(REPORTS_DIR)`

- [ ] **SEC-M8** — Ajouter TLS entre les services Docker
  - Fix : reverse proxy Traefik/Nginx avec terminaison TLS, mTLS inter-services

- [ ] **SEC-M9** — Sécuriser les API keys LLM dans le service garak
  - Fix : Docker secrets au lieu de variables d'environnement

- [ ] **SEC-M10** — Isoler la DB DefectDojo sur un réseau dédié
  - Fix : réseau Docker séparé `defectdojo-net`, accès restreint au container Django

- [ ] **SEC-M11** — Ajouter trap handler dans `runner.sh` pour cleanup
  - Fix : `trap 'docker compose kill 2>/dev/null; exit 130' INT TERM EXIT`

### 🔵 LOW (2)

- [ ] **SEC-L1** — Valider `RATE_LIMIT` comme entier dans `runner.sh`
  - Fix : `[[ "$RATE_LIMIT" =~ ^[0-9]+$ ]] || error 'Rate limit must be integer'`

- [ ] **SEC-L2** — Signer les artefacts CI (checksums SHA256 + Cosign)

---

## 2. QUALITÉ DU CODE — Manquements

### 🟠 HIGH

- [ ] **QA-H1** — Augmenter la couverture de tests (7 fichiers sur 118 ≈ 6%)
  - Priorités : orchestrator/flows, llm/agent_tools, memory/client, scope/enforcer, graph/dependency_graph
  - Objectif : ≥ 60% coverage (lignes + branches)

- [ ] **QA-H2** — Ajouter validation Pydantic sur tous les inputs (0 modèle actuellement)
  - Priorités : arguments LLM agent_tools, payloads engine, scope parser, smart_scan config
  - Fichier à créer : `models.py` avec BaseModel pour chaque module

- [ ] **QA-H3** — Unifier les 3 points d'entrée pipeline (runner.sh, Makefile, orchestrator)
  - runner.sh est dupliqué avec le Makefile — factoriser en un seul orchestrateur

- [ ] **QA-H4** — Supprimer le `.env` committé avec target réel
  - Fichier : `.env` → ajouter dans `.gitignore`, ne garder que `.env.example`

### 🟡 MEDIUM

- [ ] **QA-M1** — Remplacer `sys.path.insert(0, ...)` par un vrai package Python avec `__init__.py`
  - Fichiers : 10+ scanners + tous les tests

- [ ] **QA-M2** — Ajouter type checking (mypy / pyright) dans le CI
  - Objectif : `mypy --strict` sur scripts/ au minimum

- [ ] **QA-M3** — Ajouter linting (ruff) dans le CI
  - Fix : `ruff check .` + `ruff format --check .`

- [ ] **QA-M4** — Pinner toutes les dépendances Python avec versions exactes
  - Fichiers : `requirements-*.txt` → ajouter `==` versions + hashes

- [ ] **QA-M5** — Purger automatiquement les rapports anciens (pas de rotation actuellement)
  - Fix : cron ou script nettoyant `reports/` > 30 jours

- [ ] **QA-M6** — Ajouter un CI trigger sur les PR (actuellement manual dispatch + weekly cron uniquement)

---

## 3. ARCHITECTURE — Améliorations structurelles

### 🟠 HIGH

- [ ] **ARCH-H1** — Sandboxer le LLM agent (`shell=True` + blocklist faible ~12 patterns)
  - Fix : supprimer `shell=True`, utiliser `subprocess.run(cmd_list)`, sandbox Docker dédié
  - Fichier : `llm/agent_tools.py`

- [ ] **ARCH-H2** — Ajouter un système d'authentification/autorisation au Dashboard
  - NextAuth.js + session + roles (admin, viewer, readonly)

### 🟡 MEDIUM

- [ ] **ARCH-M1** — Séparer la config en layers (base → profile → user override)
  - Actuellement : configs/ mélange les présets et les overrides

- [ ] **ARCH-M2** — Ajouter une API de status/health unifiée pour tous les services
  - Endpoint `/api/health` renvoyant l'état de chaque service

- [ ] **ARCH-M3** — Centraliser la gestion des secrets (Vault ou SOPS)
  - Remplacer les `.env` par un système de secrets management

---

## 4. INTÉGRATIONS SOTA — Nouvelles fonctionnalités

### ⭐ P0 — Obligatoires (impact immédiat)

- [ ] **SOTA-P0-1** — Intégrer Syft + Grype pour SCA/SBOM
  - Génération CycloneDX/SPDX automatique, scan de vulns sur les deps
  - Effort : ~25h | ROI : ⭐⭐⭐⭐⭐
  - Raison : conformité SBOM obligatoire (EU CRA, NIST SSDF)

- [ ] **SOTA-P0-2** — Étendre Checkov (déjà intégré) avec policies custom
  - ✅ Checkov déjà présent dans docker-compose → ajouter policies CIS/PCI-DSS custom + output SARIF + intégration CI
  - Effort : ~10h | ROI : ⭐⭐⭐⭐⭐

- [ ] **SOTA-P0-3** — Intégrer Lakera Guard pour la sécurité LLM
  - Détection injection/jailbreak sur les inputs/outputs LLM
  - Effort : ~15h | ROI : ⭐⭐⭐⭐⭐

- [ ] **SOTA-P0-4** — Étendre Garak pour le AI Red Teaming complet
  - Prompts adversariaux, extraction de modèle, data poisoning RAG
  - Effort : ~30h | ROI : ⭐⭐⭐⭐⭐

- [ ] **SOTA-P0-5** — Standardiser les outputs en format SARIF
  - Interopérable GitHub/GitLab code scanning, findings en PR comments
  - Effort : ~18h | ROI : ⭐⭐⭐⭐

- [ ] **SOTA-P0-6** — SPDX/CycloneDX standard output dans merge-reports
  - Conformité réglementaire 2025-2026
  - Effort : ~15h | ROI : ⭐⭐⭐⭐⭐

### ⭐ P1 — Hautement recommandés (valeur élevée)

- [ ] **SOTA-P1-1** — Intégrer Kiterunner pour API discovery
  - ML-trained wordlists, OpenAPI schema inference, 2x plus rapide que ffuf pour les APIs
  - Effort : ~18h

- [ ] **SOTA-P1-2** — Ajouter ProjectDiscovery Uncover (OSINT aggregator)
  - Agrège Shodan, Censys, Fofa, Zoomeye en un seul tool
  - Effort : ~12h

- [ ] **SOTA-P1-3** — Monitoring Certificate Transparency en continu
  - Détection précoce de nouveaux sous-domaines, typosquatting
  - Effort : ~12h

- [ ] **SOTA-P1-4** — Upgrade Nuclei vers v3.2+ (JS matchers, WebSocket scan)
  - Effort : ~8h (quick win)

- [ ] **SOTA-P1-5** — Intégrer Schemathesis pour API fuzzing
  - Property-based testing depuis OpenAPI specs
  - Effort : ~20h

- [ ] **SOTA-P1-6** — Ajouter CodeQL + ML-enhanced rules
  - Analyse taint + data flow, complément à Semgrep
  - Effort : ~35h

- [ ] **SOTA-P1-7** — Intégrer OSV-Scanner (Google)
  - Meilleure couverture OSS vulns que NVD
  - Effort : ~12h

- [ ] **SOTA-P1-8** — Intégrer OWASP Dependency-Track
  - Gestion SBOM centralisée, tendances historiques
  - Effort : ~30h

- [ ] **SOTA-P1-9** — Ajouter CloudList (ProjectDiscovery) pour recon cloud
  - Énumération S3, Azure Blobs, GCS, EC2, RDS
  - Effort : ~15h

- [ ] **SOTA-P1-10** — Ajouter monitoring continu Shodan/Censys (Shodan CLI déjà intégré)
  - ✅ `shodan-cli` déjà dans docker-compose → ajouter alertes temps réel, cron scheduling, Censys API
  - Effort : ~18h

- [ ] **SOTA-P1-11** — Intégrer Kube-Bench + Kube-Hunter
  - CIS K8s Benchmark + pentest K8s actif
  - Effort : ~30h

- [ ] **SOTA-P1-12** — Prowler pour audit multi-cloud (AWS/GCP/Azure)
  - 600+ checks CIS, alternative à CloudSploit
  - Effort : ~20h

- [ ] **SOTA-P1-13** — Étendre GraphQL security avec InQL + graphql-cop (graphw00f déjà intégré)
  - ✅ `graphw00f` déjà dans docker-compose (fingerprinting) → ajouter InQL (schema extraction, batch query abuse) + graphql-cop (audit OWASP)
  - Effort : ~20h

- [ ] **SOTA-P1-14** — Enrichir DefectDojo avec LLM dedup/summarization
  - Réduction 70% du temps de review, clustering de findings
  - Effort : ~30h

- [ ] **SOTA-P1-15** — Corrélation VulnDB/NVD (CVSS + exploit maturity)
  - Priorisation basée sur l'exploitabilité réelle
  - Effort : ~15h

- [ ] **SOTA-P1-16** — Mapping compliance (OWASP ASVS, NIST, PCI-DSS)
  - Mapping CWE → contrôles ASVS/NIST pour les rapports
  - Effort : ~35h

- [ ] **SOTA-P1-17** — OpenTelemetry + Grafana pour observabilité des scans
  - Traces, métriques, dashboards de performance des scanners
  - Effort : ~60h

- [ ] **SOTA-P1-18** — Scheduling continu avec Prefect (cron scans)
  - Weekly recon, daily SAST, monthly full audit
  - Effort : ~18h

- [ ] **SOTA-P1-19** — Pipeline d'alertes (Slack, PagerDuty, Teams)
  - Notification immédiate sur findings CRITICAL
  - Effort : ~20h

- [ ] **SOTA-P1-20** — HashiCorp Vault pour secrets management
  - Secrets dynamiques, rotation, audit trail
  - Effort : ~50h

- [ ] **SOTA-P1-21** — Socket.dev pour détection supply chain malveillante
  - Behavorial analysis npm/pip packages, typosquatting
  - Effort : ~20h

- [ ] **SOTA-P1-22** — Étendre TruffleHog + Gitleaks (déjà intégrés) avec patterns custom
  - ✅ `trufflehog` et `gitleaks` déjà dans docker-compose → ajouter regex internes pour API keys custom, tokens propriétaires, secrets métier
  - Effort : ~8h

- [ ] **SOTA-P1-23** — Conformance testing (OAuth 2.1, RFC 9728)
  - Compliance edge cases = vulnérabilités
  - Effort : ~50h

### ⭐ P2 — Nice-to-have (backlog)

- [ ] **SOTA-P2-1** — Caido proxy (alternative moderne à Burp/ZAP)
  - Rust, 10x plus rapide, HTTP/2 natif, $150/an vs $4k Burp
  - Effort : ~50h

- [ ] **SOTA-P2-2** — AFL++ avec custom mutators Python
  - Fuzzing ML-guided pour API servers, binary parsers
  - Effort : ~25h

- [ ] **SOTA-P2-3** — Étendre Dalfox (déjà intégré) avec DalScan headless verification
  - ✅ `dalfox` déjà dans docker-compose → ajouter DalScan pour vérification DOM XSS headless, réduit false positives de 40-60%
  - Effort : ~6h

- [ ] **SOTA-P2-4** — Étendre CRLFuzz + Smuggler (déjà intégrés) avec H2 smuggling
  - ✅ `crlfuzz` et `smuggler` déjà dans docker-compose → ajouter chaîne CRLF→smuggling automatisée + output SARIF
  - Effort : ~8h

- [ ] **SOTA-P2-5** — Intégrer ParamSpider en complément d'Arjun (déjà intégré)
  - ✅ `arjun` déjà dans docker-compose → ajouter ParamSpider (Wayback + GitHub repo mining) pour discovery passive
  - Effort : ~8h

- [ ] **SOTA-P2-6** — gRPC fuzzing (grpcurl + custom fuzzer)
  - Microservices, attack surface négligée
  - Effort : ~45h

- [ ] **SOTA-P2-7** — WebSocket++ fuzzer complet
  - Injection, auth bypass, DoS large messages
  - Effort : ~25h

- [ ] **SOTA-P2-8** — H2cSmuggler (HTTP/2 smuggling)
  - Effort : ~25h

- [ ] **SOTA-P2-9** — Scan comparison & diff (regression tracking)
  - Effort : ~30h

- [ ] **SOTA-P2-10** — Cosign (container image signing)
  - Effort : ~25h

- [ ] **SOTA-P2-11** — LLM exec summary generator
  - 1-page business summary depuis les findings détaillés
  - Effort : ~20h

- [ ] **SOTA-P2-12** — Supply chain attack simulation
  - Typosquatting, build poisoning, CI/CD compromise
  - Effort : ~70h

- [ ] **SOTA-P2-13** — Chaos engineering pour sécurité (Gremlin + security)
  - Tester les failure modes auth (Redis down → bypass ?)
  - Effort : ~60h

- [ ] **SOTA-P2-14** — ML-powered false positive deduplication
  - Modèle entraîné sur l'historique des findings
  - Effort : ~50h

### ⭐ P3 — Futur / Recherche

- [ ] **SOTA-P3-1** — Digital Twin (réplication d'environnement)
  - Tests destructifs en sécurité, effort très élevé (~100h+)

- [ ] **SOTA-P3-2** — Automated exploit generation
  - Finding → POC fonctionnel automatiquement (~80h+)

- [ ] **SOTA-P3-3** — Zero-day hunting framework
  - Hypothesis generation + fuzzing + crash analysis (~100h+)

- [ ] **SOTA-P3-4** — Gotestwaf (WAF rule validation)
  - Utile pour les bug bounties internes uniquement (~30h)

---

## 5. OUTILS DÉJÀ INTÉGRÉS (référence)

> Ces outils sont déjà présents dans `docker-compose.yml`. Les entrées SOTA ci-dessus
> les marquent ✅ et recommandent uniquement des **extensions/améliorations**.

| Service docker-compose | Catégorie | État |
|------------------------|-----------|------|
| `nuclei`, `nuclei-full`, `nuclei-subs` | Vuln scanning + subdomain | ✅ Présent (upgrade v3.2+ recommandé) |
| `checkov` | IaC scanning | ✅ Présent (policies custom recommandées) |
| `garak` | AI red teaming | ✅ Présent (extension scénarios recommandée) |
| `shodan-cli` | OSINT reconnaissance | ✅ Présent (monitoring continu recommandé) |
| `dalfox` | XSS scanner | ✅ Présent (DalScan headless recommandé) |
| `crlfuzz` | CRLF injection | ✅ Présent (chaîne smuggling recommandée) |
| `smuggler` | HTTP request smuggling | ✅ Présent (output SARIF recommandé) |
| `arjun` | Parameter discovery | ✅ Présent (ParamSpider en complément) |
| `graphw00f` | GraphQL fingerprinting | ✅ Présent (InQL + graphql-cop recommandés) |
| `restler` | REST API fuzzing | ✅ Présent |
| `subfinder` | Subdomain enumeration | ✅ Présent |
| `katana` | Web crawler | ✅ Présent |
| `semgrep` | SAST | ✅ Présent (CI integration manquante) |
| `gitleaks` | Secrets detection | ✅ Présent (CI integration manquante) |
| `trufflehog` | Secrets detection | ✅ Présent (patterns custom recommandés) |
| `waf-bypass` | WAF evasion | ✅ Présent |
| `commix` | Command injection | ✅ Présent |
| `wapiti` | Web vuln scanner | ✅ Présent |
| `hydra` | Brute force | ✅ Présent |
| `brute-forcer` | Credential testing | ✅ Présent |

---

## 6. RÉCAPITULATIF

| Catégorie | 🔴 CRITICAL | 🟠 HIGH | 🟡 MEDIUM | 🔵 LOW | ⭐ SOTA | Total |
|-----------|:-----------:|:-------:|:---------:|:------:|:------:|:-----:|
| Sécurité | 4 | 12 | 11 | 2 | — | 29 |
| Qualité code | — | 4 | 6 | — | — | 10 |
| Architecture | — | 2 | 3 | — | — | 5 |
| SOTA P0 | — | — | — | — | 6 | 6 |
| SOTA P1 | — | — | — | — | 23 | 23 |
| SOTA P2 | — | — | — | — | 14 | 14 |
| SOTA P3 | — | — | — | — | 4 | 4 |
| **Total** | **4** | **18** | **20** | **2** | **47** | **91** |

> **Note :** 7 entrées SOTA marquées ✅ concernent des outils déjà intégrés —
> l'effort est réduit (extension/config uniquement, pas d'intégration from scratch).
> 20 services Docker déjà présents servent de base (voir §5).

### Ordre d'exécution recommandé

1. **Semaine 1** : SEC-C1 → C4 (4 CRITICAL sécurité)
2. **Semaine 2** : SEC-H1 → H6, QA-H4 (fix .env), ARCH-H1 (sandbox LLM)
3. **Semaine 3** : SEC-H7 → H12, QA-H1 (tests), QA-H2 (Pydantic)
4. **Semaine 4** : SOTA-P0-1 → P0-6 (quick wins SOTA — P0-2 et P0-4 déjà partiellement intégrés)
5. **Sprint 2** : SOTA-P1 top 10 (Kiterunner, Nuclei upgrade, Schemathesis, CT monitoring...)
6. **Sprint 3** : SEC-M*, QA-M*, ARCH-M* (dette technique)
7. **Sprint 4+** : SOTA-P1 restants + P2 sélectifs

---

*Estimation totale : ~750-950 heures de développement pour tout couvrir (réduit de ~50h grâce aux 7 outils déjà intégrés).*
*Quick wins (P0 + top P1 + CRITICAL fixes) : ~190 heures.*
