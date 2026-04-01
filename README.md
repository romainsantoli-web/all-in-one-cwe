# 🛡️ Security All-in-One CWE — Bug Bounty Testing Suite


Suite complète de **59 outils** de sécurité offensive pour le bug bounty, organisée par catégorie CWE.
Tous les outils tournent via Docker Compose — un seul `make run` pour tout lancer.

---

## 📋 Table des matières

- [Installation rapide](#-installation-rapide)
- [Architecture](#-architecture)
- [Les 59 outils](#-les-59-outils)
- [Tutoriel d'utilisation](#-tutoriel-dutilisation)
- [Commandes Make](#-commandes-make)
- [Mapping CWE → Outil](#-mapping-cwe--outil)
- [Reporting](#-reporting)
- [Profils Docker](#-profils-docker)
- [Dépannage](#-dépannage)

---

## 🚀 Installation rapide

```bash
# Cloner le repo
git clone https://github.com/VOTRE_USERNAME/security-all-in-one-cwe.git
cd security-all-in-one-cwe

# Construire et tirer toutes les images
make setup

# Lancer un scan complet
make run TARGET=https://target.example.com
```

### Prérequis

| Ressource | Minimum | Recommandé |
|-----------|---------|------------|
| Docker | >= 24.0 + Compose v2 | Dernière stable |
| RAM | 8 Go | 16 Go |
| Disque | 20 Go | 40 Go |
| OS | macOS / Linux | — |

---

## 🏗️ Architecture

```
security-all-in-one-cwe/
├── docker-compose.yml          # 50 services Docker
├── runner.sh                   # Orchestrateur séquentiel (36 sections)
├── Makefile                    # 48 targets (make run, make xss, etc.)
├── configs/                    # Configs Nuclei, ZAP, Semgrep, Trivy, Gitleaks
├── custom-rules/               # Templates Nuclei, Semgrep, CodeQL custom
├── scripts/                    # merge-reports.py, cwe-summary.py, defectdojo-import.sh
└── reports/                    # Résultats par outil (47 sous-dossiers)
```

---

## 🔧 Les 59 outils

### 🎯 DAST — Dynamic Application Security Testing

| # | Outil | Description | CWE principaux | Profil |
|---|-------|-------------|----------------|--------|
| 1 | **Nuclei** | Scanner DAST avec templates custom | 79, 89, 78, 918, 611, 352 | default |
| 2 | **Nuclei Full** | Nuclei avec tous les templates officiels | idem | `full` |
| 3 | **Nuclei Subs** | Nuclei sur liste de sous-domaines | idem | `subs` |
| 4 | **OWASP ZAP** | Framework de scan automatisé | 79, 89, 78, 352, 601 | default |
| 5 | **ZAP Baseline** | Scan ZAP rapide (baseline) | idem | default |
| 6 | **ZAP Full** | Scan ZAP complet avec spider | idem | `full` |
| 7 | **ZAP GUI** | Interface graphique ZAP | idem | `gui` |
| 8 | **SQLMap** | Injection SQL automatisée | 89 | default |
| 9 | **SSTImap** | Server-Side Template Injection | 1336, 94 | default |
| 10 | **Nikto** | Scanner web classique (misconfig, info leak) | 200, 16, 538, 693 | default |

### 🌐 XSS — Cross-Site Scripting

| # | Outil | Description | CWE | Profil |
|---|-------|-------------|-----|--------|
| 11 | **Dalfox** | Scanner XSS avancé, DOM/Reflected/Stored | 79 | `xss` |

### 🔐 JWT — JSON Web Token

| # | Outil | Description | CWE | Profil |
|---|-------|-------------|-----|--------|
| 12 | **jwt_tool** | Tests JWT (none alg, key confusion, brute) | 287, 345, 347 | `jwt` |

### 🕸️ DNS & Reconnaissance

| # | Outil | Description | CWE | Profil |
|---|-------|-------------|-----|--------|
| 13 | **Subfinder** | Enumération passive sous-domaines | 200 | `recon` |
| 14 | **OWASP Amass** | Enumération DNS complète (active+passive) | 200 | default |
| 15 | **DNSx** | Toolkit DNS (résolution, wildcard, brute) | 200, 350 | default |
| 16 | **httpx** | Probe HTTP (status, title, tech) | 200 | `recon` |
| 17 | **dnsReaper** | Détection subdomain takeover | 16 | default |
| 18 | **Subdominator** | Détection subdomain takeover avancée | 16 | default |
| 19 | **Naabu** | Port scanning rapide | 200, 16 | `recon` |
| 20 | **Katana** | Crawler web + extraction JS links | 200 | `recon` |

### 🛡️ WAF & Bypass

| # | Outil | Description | CWE | Profil |
|---|-------|-------------|-----|--------|
| 21 | **Wafw00f** | Fingerprinting WAF | 693 | `waf` |
| 22 | **Bypass-403** | Contournement restrictions 403 | 284, 862 | `waf` |

### 🔍 Fuzzing & Discovery

| # | Outil | Description | CWE | Profil |
|---|-------|-------------|-----|--------|
| 23 | **ffuf** | Fuzzer web ultra-rapide (dirs, params, vhosts) | 538, 200 | `fuzz` |
| 24 | **Feroxbuster** | Enumération forcée de contenu | 538, 200 | `fuzz` |
| 25 | **Arjun** | Découverte de paramètres HTTP | 200 | default |

### 🔒 TLS / SSL

| # | Outil | Description | CWE | Profil |
|---|-------|-------------|-----|--------|
| 26 | **testssl.sh** | Audit TLS/SSL complet | 295, 326, 327 | default |

### 🌍 CORS & Headers

| # | Outil | Description | CWE | Profil |
|---|-------|-------------|-----|--------|
| 27 | **CORScanner** | Détection CORS misconfiguration | 942, 346 | default |

### 📡 Network

| # | Outil | Description | CWE | Profil |
|---|-------|-------------|-----|--------|
| 28 | **Nmap** | Port & service scanning avancé | 200, 16 | `network` |

### 🕵️ Fingerprinting & Tech Detection

| # | Outil | Description | CWE | Profil |
|---|-------|-------------|-----|--------|
| 29 | **WhatWeb** | Identification technologies web | 200 | default |
| 30 | **CMSeeK** | Détection CMS + vulnérabilités | 200 | `cms` |

### 📊 API Security

| # | Outil | Description | CWE | Profil |
|---|-------|-------------|-----|--------|
| 31 | **Graphw00f** | Fingerprinting GraphQL | 200 | default |
| 32 | **Clairvoyance** | Introspection bypass GraphQL | 200, 284, 639 | `graphql` |
| 33 | **Cherrybomb** | Audit OpenAPI/Swagger | 200, 284 | `openapi` |

### ☁️ Cloud

| # | Outil | Description | CWE | Profil |
|---|-------|-------------|-----|--------|
| 34 | **cloud_enum** | Enumération buckets/blobs (AWS, Azure, GCP) | 284, 922 | default |

### 🔓 Injection & Exploitation

| # | Outil | Description | CWE | Profil |
|---|-------|-------------|-----|--------|
| 35 | **CRLFuzz** | CRLF injection scanner | 113, 93 | default |
| 36 | **SSRFmap** | SSRF exploitation framework | 918 | `ssrf` |
| 37 | **ppmap** | Prototype pollution scanner | 1321 | `prototype` |
| 38 | **log4j-scan** | Détection Log4Shell (CVE-2021-44228) | 502, 917 | default |

### 🔑 Secrets & SAST

| # | Outil | Description | CWE | Profil |
|---|-------|-------------|-----|--------|
| 39 | **Semgrep** | Analyse statique multi-langage | 89, 78, 79, 327, 502 | default |
| 40 | **Gitleaks** | Secrets dans repos Git | 798, 259, 312 | default |
| 41 | **TruffleHog** | Secrets vérifiés (testé actif) | 798, 259, 522 | default |

### 📦 SCA — Software Composition Analysis

| # | Outil | Description | CWE | Profil |
|---|-------|-------------|-----|--------|
| 42 | **Trivy** | Scan filesystem (vulns, secrets, misconfig) | 1395, 16 | default |
| 43 | **Trivy Image** | Scan d'images Docker | idem | `image` |
| 44 | **Dependency-Check** | OWASP SCA (CVEs des dépendances) | 1395 | default |
| 45 | **RetireJS** | SCA pour librairies JavaScript frontend | 1395 | `frontend-sca` |
| 46 | **Dockle** | Best practices conteneurs Docker | 16 | `container` |

### 🔬 Binary & LLM

| # | Outil | Description | CWE | Profil |
|---|-------|-------------|-----|--------|
| 47 | **cwe_checker** | Analyse binaire (buffer overflow, UAF) | 120-122, 416, 476 | default |
| 48 | **cve-bin-tool** | CVE dans binaires compilés | 1395 | default |

### � API Discovery & Secret Leakage

| # | Outil | Description | CWE | Profil |
|---|-------|-------------|-----|--------|
| 49 | **api-discovery** | Découverte d'endpoints API via JS bundles, configs inline, source maps | 200, 540 | `python-scanners` |
| 50 | **secret-leak** | Détection de secrets/tokens dans réponses HTTP, JS, source maps | 312, 540, 615 | `python-scanners` |

### �📸 Autres

| # | Outil | Description | Profil |
|---|-------|-------------|--------|
| — | **Gowitness** | Screenshots web automatisés | `screenshot` |
| — | **JSLuice** | Extraction secrets/URLs depuis JavaScript | `js` |
| — | **theHarvester** | OSINT (emails, noms, sous-domaines) | `osint` |
| — | **Interactsh** | Serveur out-of-band (callbacks) | `oob` |
| — | **garak** | Tests prompt injection LLM | default |

---

## 📖 Tutoriel d'utilisation

### 1. Scan complet sur une cible web

```bash
# Scan de base — lance nuclei, zap-baseline, sqlmap, sstimap + tools réseau
./runner.sh https://target.example.com --domain target.example.com --rate-limit 30

# Ou via Make
make run TARGET=https://target.example.com DOMAIN=target.example.com
```

### 2. Scan complet étendu (toutes les options activées)

```bash
./runner.sh https://target.example.com \
  --domain target.example.com \
  --rate-limit 30 \
  --full
```

### 3. Outils individuels

#### 🎯 DAST uniquement
```bash
# Nuclei + ZAP seulement
make dast TARGET=https://target.example.com

# SQL Injection
make sqli TARGET=https://target.example.com

# SSTI
make ssti TARGET=https://target.example.com
```

#### 🌐 XSS (Dalfox)
```bash
make xss TARGET=https://target.example.com

# Ou directement via Docker
docker compose run --rm dalfox /app/dalfox url https://target.example.com/search?q=test \
  -o /output/scan.json --format json
```

#### 🔐 JWT Testing
```bash
# Fournir un token JWT à tester
JWT_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." make jwt
```

#### 🕸️ Reconnaissance DNS
```bash
# Enumération sous-domaines (subfinder + httpx + naabu + katana)
make recon DOMAIN=target.example.com

# Amass seul (plus lent, plus complet)
make amass-enum DOMAIN=target.example.com

# DNSx toolkit
make dns-toolkit DOMAIN=target.example.com
```

#### 🛡️ WAF Detection & Bypass
```bash
make waf TARGET=https://target.example.com
```

#### 🔍 Fuzzing (dirs, params)
```bash
# ffuf + feroxbuster + arjun
make fuzz TARGET=https://target.example.com
```

#### 🔒 TLS/SSL Audit
```bash
make tls TARGET=https://target.example.com
```

#### 🌍 CORS Misconfiguration
```bash
make cors DOMAIN=target.example.com
```

#### 📡 Port Scanning (Nmap)
```bash
make network DOMAIN=target.example.com
```

#### 🕵️ CMS Detection
```bash
make cms TARGET=https://target.example.com
```

#### 📊 API Security — GraphQL
```bash
# Fingerprinting GraphQL
make api TARGET=https://target.example.com/graphql

# Deep introspection bypass
make graphql-deep TARGET=https://target.example.com/graphql
```

#### 📊 API Security — OpenAPI
```bash
# Placer l'OpenAPI spec dans reports/cherrybomb/openapi.json, puis :
make openapi
```

#### ☁️ Cloud Enumeration
```bash
make cloud DOMAIN=target.example.com
```

#### 🔓 Injections avancées
```bash
# CRLF Injection
make crlf TARGET=https://target.example.com

# SSRF
make ssrf TARGET=https://target.example.com

# Prototype Pollution
make proto-pollution TARGET=https://target.example.com

# Log4Shell
make log4shell TARGET=https://target.example.com
```

#### 🔑 Secrets scanning (sur un repo local)
```bash
make secrets REPO=/chemin/vers/repo

# Ou individuellement
docker compose run --rm gitleaks detect --source=/src --report-path=/output/scan.json --report-format=json -v
docker compose run --rm trufflehog filesystem --directory=/src --json --only-verified
```

#### 📦 SCA (dépendances)
```bash
# Filesystem scan
make sca CODE=/chemin/vers/code

# Docker image scan
make sca-image IMAGE=nginx:latest

# Conteneur best practices
make container-lint IMAGE=myapp:latest

# Frontend JavaScript SCA
make frontend-sca CODE=/chemin/vers/frontend
```

#### 🔬 Binary analysis
```bash
make binary BIN=/chemin/vers/binaire
```

#### 📸 Screenshots
```bash
make screenshot TARGET=https://target.example.com
```

#### 🕵️ OSINT
```bash
make osint DOMAIN=target.example.com
```

#### 📜 JavaScript Analysis
```bash
make js-analysis TARGET=https://target.example.com
```

#### 🔎 API Discovery & Secret Leakage
```bash
# Découverte d'endpoints API via JS bundles, configs inline, source maps
make api-discovery TARGET=https://target.example.com

# Détection de secrets/tokens dans les réponses HTTP et fichiers JS
make secret-leak TARGET=https://target.example.com

# Les deux à la fois (inclus dans python-scanners)
make python-scanners TARGET=https://target.example.com
```

### 4. Sélection d'outils spécifiques

```bash
# Lancer SEULEMENT nuclei et sqlmap
./runner.sh https://target.example.com --only nuclei,sqlmap

# Tout SAUF garak et cwe-checker
./runner.sh https://target.example.com --skip garak,cwe-checker
```

### 5. Générer les rapports

```bash
# Fusionner tous les résultats en un seul JSON
make report

# Résumé CWE
make summary

# Importer dans DefectDojo
make defectdojo           # Lance le dashboard (port 8443)
make defectdojo-import    # Import automatique
```

---

## 🎯 Commandes Make — Référence complète

| Commande | Description | Requires |
|----------|-------------|----------|
| `make setup` | Pull images + build custom | — |
| `make run` | Scan complet | TARGET |
| `make full` | Scan étendu (plus lent) | TARGET |
| `make dast` | Nuclei + ZAP | TARGET |
| `make sqli` | SQLMap | TARGET |
| `make ssti` | SSTImap | TARGET |
| `make xss` | Dalfox XSS | TARGET |
| `make jwt` | jwt_tool | JWT_TOKEN env |
| `make classic-scan` | Nikto | TARGET |
| `make dns` | dnsReaper + Subdominator | DOMAIN |
| `make recon` | httpx + subfinder + naabu + katana | DOMAIN |
| `make amass-enum` | OWASP Amass | DOMAIN |
| `make dns-toolkit` | DNSx | DOMAIN |
| `make waf` | wafw00f + bypass-403 | TARGET |
| `make fuzz` | ffuf + feroxbuster + arjun | TARGET |
| `make tls` | testssl.sh | TARGET |
| `make cors` | CORScanner | DOMAIN |
| `make network` | Nmap | DOMAIN |
| `make fingerprint` | WhatWeb | TARGET |
| `make cms` | CMSeeK | TARGET |
| `make api` | Graphw00f | TARGET |
| `make graphql-deep` | Clairvoyance | TARGET |
| `make openapi` | Cherrybomb | openapi.json |
| `make cloud` | cloud_enum | DOMAIN |
| `make crlf` | CRLFuzz | TARGET |
| `make ssrf` | SSRFmap | TARGET |
| `make proto-pollution` | ppmap | TARGET |
| `make log4shell` | log4j-scan | TARGET |
| `make sast` | Semgrep | CODE |
| `make secrets` | Gitleaks + TruffleHog | REPO |
| `make sca` | Trivy + Dependency-Check | CODE |
| `make sca-image` | Trivy image | IMAGE |
| `make container-lint` | Dockle | IMAGE |
| `make frontend-sca` | RetireJS | CODE |
| `make binary` | cwe_checker | BIN |
| `make screenshot` | Gowitness | TARGET |
| `make js-analysis` | JSLuice | TARGET |
| `make osint` | theHarvester | DOMAIN |
| `make oob` | Interactsh | — |
| `make report` | Fusionner rapports | — |
| `make summary` | Résumé CWE | — |
| `make defectdojo` | Lancer DefectDojo | — |
| `make zap-gui` | ZAP GUI (port 8080) | — |
| `make clean` | Supprimer rapports | — |
| `make nuke` | Tout supprimer (DESTRUCTIF) | — |
| `make idor` | IDOR scanner (CWE-639) | TARGET + AUTH_TOKEN |
| `make auth-bypass` | Auth bypass (CWE-287/284/915) | TARGET |
| `make user-enum` | User enumeration (CWE-203/204) | TARGET |
| `make notif-inject` | Notification injection (CWE-74/79) | TARGET + AUTH_TOKEN |
| `make redirect-cors` | Open redirect + CORS (CWE-601/942) | TARGET |
| `make oidc-audit` | OIDC/OAuth audit (CWE-200/287/522) | TARGET |
| `make bypass-403-adv` | 403 bypass + RPC discovery (CWE-284) | TARGET |
| `make ssrf-scan` | SSRF scanner (CWE-918) | TARGET |
| `make xss-scan` | XSS + SSTI + CSP (CWE-79/693/1336) | TARGET + AUTH_TOKEN |
| `make api-discovery` | API discovery via JS bundles (CWE-200/540) | TARGET |
| `make secret-leak` | Secret/token leakage (CWE-312/540/615) | TARGET |
| `make python-scanners` | All 11 Python scanners | TARGET + AUTH_TOKEN |

---

## 🗺️ Mapping CWE → Outil

| CWE | Vulnérabilité | Outils |
|-----|---------------|--------|
| CWE-16 | Misconfiguration | Nuclei, Nikto, Naabu, Nmap, Dockle, Trivy |
| CWE-22 | Path Traversal | Nuclei, ZAP, Semgrep |
| CWE-78 | OS Command Injection | Nuclei, ZAP, Semgrep |
| CWE-79 | XSS | Nuclei, ZAP, Dalfox, Semgrep, **xss-scanner** |
| CWE-89 | SQL Injection | SQLMap, Nuclei, ZAP, Semgrep |
| CWE-93/113 | CRLF Injection | CRLFuzz, Nuclei |
| CWE-94 | Code Injection | SSTImap, Semgrep |
| CWE-120-122 | Buffer Overflow | cwe_checker |
| CWE-200 | Information Exposure | Nuclei, httpx, WhatWeb, ffuf, Feroxbuster, **oidc-audit**, **api-discovery** |
| CWE-259/798 | Hardcoded Credentials | Gitleaks, TruffleHog, Semgrep, Trivy |
| CWE-284 | Access Control | ZAP, Bypass-403, Clairvoyance, **bypass-403-advanced** |
| CWE-287 | Authentication | ZAP, jwt_tool, **auth-bypass**, **oidc-audit** |
| CWE-295/326/327 | Crypto/TLS Issues | testssl.sh, Trivy, Semgrep |
| CWE-312 | Cleartext Storage | Gitleaks, TruffleHog, Trivy, **secret-leak** |
| CWE-345/347 | JWT Verification | jwt_tool |
| CWE-346/942 | CORS Misconfiguration | CORScanner, **redirect-cors** |
| CWE-350 | DNS Issues | DNSx, dnsReaper |
| CWE-352 | CSRF | ZAP, Nuclei |
| CWE-416 | Use After Free | cwe_checker |
| CWE-476 | Null Pointer Deref | cwe_checker |
| CWE-502/917 | Deserialization/Log4j | log4j-scan, Semgrep |
| CWE-538 | File/Dir Listing | ffuf, Feroxbuster, Nikto |
| CWE-601 | Open Redirect | Nuclei, ZAP, **redirect-cors** |
| CWE-611 | XXE | Nuclei, ZAP |
| CWE-639 | IDOR | Clairvoyance, **idor-scanner** |
| CWE-693 | WAF Bypass | Wafw00f, Bypass-403, **bypass-403-advanced** |
| CWE-918 | SSRF | SSRFmap, Nuclei, Semgrep, **ssrf-scanner** |
| CWE-922 | Insecure Storage | cloud_enum |
| CWE-1321 | Prototype Pollution | ppmap |
| CWE-1336 | SSTI | SSTImap, Nuclei, **xss-scanner** |
| CWE-1395 | Known Vulns (SCA) | Trivy, Dependency-Check, RetireJS, cve-bin-tool |
| CWE-1427 | LLM Prompt Injection | garak |
| CWE-74/93 | Notification Injection | **notif-inject** |
| CWE-203/204 | User Enumeration | **user-enum** |
| CWE-522 | Weak Credentials | **oidc-audit** |
| CWE-915 | Mass Assignment | **auth-bypass** |
| CWE-540 | Sensitive Info in Source | **api-discovery**, **secret-leak** |
| CWE-615 | Info Leak in Comments | **secret-leak** |

---

## 🐳 Profils Docker

Les profils permettent d'activer sélectivement des groupes d'outils :

```bash
# Lancer uniquement les outils de recon
docker compose --profile recon up

# Combiner plusieurs profils
docker compose --profile recon --profile fuzz --profile waf up
```

| Profil | Outils activés |
|--------|----------------|
| `recon` | httpx, subfinder, naabu, katana |
| `fuzz` | ffuf, feroxbuster |
| `waf` | wafw00f, bypass-403 |
| `network` | nmap |
| `full` | nuclei-full, zap-full |
| `subs` | nuclei-subs |
| `gui` | zap-gui |
| `image` | trivy-image |
| `xss` | dalfox |
| `jwt` | jwt-tool |
| `oob` | interactsh |
| `js` | jsluice |
| `screenshot` | gowitness |
| `ssrf` | ssrfmap |
| `container` | dockle |
| `frontend-sca` | retirejs |
| `osint` | theharvester |
| `openapi` | cherrybomb |
| `prototype` | ppmap |
| `graphql` | clairvoyance |
| `cms` | cmseek |
| `python-scanners` | idor-scanner, auth-bypass, user-enum, notif-inject, redirect-cors, oidc-audit, bypass-403-advanced, ssrf-scanner, xss-scanner, api-discovery, secret-leak |
| `defectdojo` | defectdojo, defectdojo-db, defectdojo-rabbitmq |

---

## 📊 Reporting

Tous les résultats sont stockés dans `reports/<outil>/` au format JSON/JSONL.

```bash
# Fusionner tous les rapports en un fichier unifié
make report
# → reports/consolidated-report.json

# Générer un résumé par CWE
make summary
# → reports/cwe-summary.json

# Importer dans DefectDojo (dashboard web sur port 8443)
make defectdojo
make defectdojo-import
```

### Structure des rapports

```
reports/
├── nuclei/          # scan-YYYYMMDD-HHMMSS.jsonl
├── zap/             # baseline-YYYYMMDD-HHMMSS.json + .html
├── sqlmap/          # session output
├── dalfox/          # scan.json
├── nikto/           # scan.json
├── jwt-tool/        # output
├── subfinder/       # subdomains.json
├── amass/           # enum output
├── dnsx/            # dns-results.json
├── httpx/           # probe-results.json
├── wafw00f/         # waf-fingerprint
├── ffuf/            # dirs discovered
├── feroxbuster/     # dirs discovered
├── arjun/           # params discovered
├── testssl/         # tls-audit
├── corscanner/      # cors-results
├── nmap/            # port-scan
├── whatweb/         # tech stack
├── cmseek/          # cms detection
├── graphw00f/       # graphql fingerprint
├── clairvoyance/    # graphql schema
├── cherrybomb/      # openapi audit
├── cloud-enum/      # buckets found
├── crlfuzz/         # crlf-results
├── ssrfmap/         # ssrf-results
├── ppmap/           # prototype pollution
├── log4j-scan/      # log4shell results
├── semgrep/         # sast-findings.json
├── gitleaks/        # secrets.json
├── trufflehog/      # verified-secrets
├── trivy/           # vuln-scan.json
├── dependency-check/ # owasp-sca
├── retirejs/        # frontend-sca
├── dockle/          # container-lint
├── cwe-checker/     # binary analysis
├── cve-bin-tool/    # binary CVEs
├── gowitness/       # screenshots
├── jsluice/         # js-secrets
├── theharvester/    # osint results
├── interactsh/      # oob callbacks
├── garak/           # llm results
├── api-discovery/   # endpoints + source maps
├── secret-leak/     # exposed secrets/tokens
└── ...
```

---

## ❓ Dépannage

### Docker I/O error (`metadata_v2.db: input/output error`)
Problème récurrent de corruption du cache BuildKit sur macOS :
```bash
docker builder prune -af
# Si ça échoue aussi :
pkill -9 -f com.docker
open -a "Docker Desktop"
# Attendre que Docker redémarre, puis :
docker builder prune -af
```

### Image manquante après crash
```bash
# Vérifier les images présentes
docker images | grep security-all-in-one

# Rebuild une image spécifique
docker compose build <service_name>

# Re-pull les images pré-construites
docker compose pull --ignore-buildable
```

### Erreur ARM64 / exec format error
Sur Apple Silicon (M1/M2/M3), certaines images nécessitent des builds spécifiques :
- `cwe_checker` : utilise `platform: linux/amd64` (émulation)
- `gowitness` / `ppmap` : compilés avec `GOTOOLCHAIN=auto` pour Go 1.25+

### Rate limiting par le WAF cible
```bash
# Réduire le rate limit
./runner.sh https://target.example.com --rate-limit 10
```

---

## ⚖️ Licence & Responsabilité

Cet outil est destiné **exclusivement** aux tests de sécurité autorisés (bug bounty, pentest contractuel).
Toute utilisation non autorisée est illégale. Les auteurs déclinent toute responsabilité.
