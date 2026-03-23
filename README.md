# 🛡️ Security All-in-One CWE — Bug Bounty Testing Suite

> ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.

Suite complète d'outils de sécurité offensive pour le bug bounty, organisée par catégorie CWE.
Tous les outils tournent via Docker Compose — un seul `make run` pour tout lancer.

## 📋 Table des matières

- [Installation rapide](#-installation-rapide)
- [Architecture](#-architecture)
- [Mapping CWE → Outil](#-mapping-cwe--outil)
- [Usage](#-usage)
- [Outils intégrés](#-outils-intégrés)
- [Reporting](#-reporting)

---

## 🚀 Installation rapide

```bash
# Cloner le repo
git clone https://github.com/VOTRE_USERNAME/security-all-in-one-cwe.git
cd security-all-in-one-cwe

# Démarrer tous les services
make setup    # pull les images + init
make run TARGET=https://target.example.com

# Ou manuellement
docker compose pull
./runner.sh https://target.example.com
```

### Prérequis

- Docker >= 24.0 + Docker Compose v2
- 8 Go RAM minimum (16 Go recommandé)
- ~20 Go d'espace disque (images Docker)

---

## 🏗️ Architecture

```
security-all-in-one-cwe/
├── docker-compose.yml          # Orchestre tous les outils
├── runner.sh                   # Script principal d'exécution séquentielle
├── Makefile                    # Raccourcis : make run, make report, make clean
├── configs/
│   ├── nuclei-config.yaml      # Config Nuclei (rate-limit, severity, etc.)
│   ├── zap-config.yaml         # Config ZAP automation framework
│   ├── semgrep-config.yaml     # Config Semgrep (rulesets)
│   ├── trivy-config.yaml       # Config Trivy
│   └── gitleaks.toml           # Config Gitleaks
├── custom-rules/
│   ├── nuclei/                 # Templates Nuclei custom (SSTI, SSRF, IDOR…)
│   ├── semgrep/                # Règles Semgrep custom
│   └── codeql/                 # Queries CodeQL custom
├── scripts/
│   ├── defectdojo-import.sh    # Import des résultats dans DefectDojo
│   ├── merge-reports.py        # Fusion des rapports en JSON unifié
│   └── cwe-summary.py          # Résumé par CWE depuis tous les rapports
├── reports/                    # Résultats par outil (générés automatiquement)
│   ├── nuclei/
│   ├── zap/
│   ├── sqlmap/
│   ├── semgrep/
│   ├── gitleaks/
│   ├── trivy/
│   ├── cwe-checker/
│   └── garak/
├── wordlists/                  # Wordlists custom pour fuzzing
├── tools/                      # Submodules Git (optionnel)
└── README.md
```

---

## 🗺️ Mapping CWE → Outil

### 1. DAST / Web Vulnerabilities

| CWE | Vulnérabilité | Outil(s) |
|-----|--------------|----------|
| CWE-79 | XSS (Reflected, Stored, DOM) | Nuclei, ZAP |
| CWE-89 | SQL Injection | SQLMap, Nuclei, ZAP |
| CWE-78 | OS Command Injection | Nuclei, Semgrep |
| CWE-918 | SSRF (Server-Side Request Forgery) | Nuclei |
| CWE-611 | XXE (XML External Entity) | Nuclei, ZAP |
| CWE-22 | Path Traversal | Nuclei, ZAP |
| CWE-639 | IDOR (Insecure Direct Object Reference) | Nuclei (custom) |
| CWE-352 | CSRF (Cross-Site Request Forgery) | ZAP, Nuclei |
| CWE-601 | Open Redirect | Nuclei, ZAP |
| CWE-444 | HTTP Request Smuggling | Nuclei |
| CWE-113 | CRLF Injection | Nuclei |
| CWE-1336 | SSTI (Server-Side Template Injection) | Nuclei, SSTImap |
| CWE-90 | LDAP Injection | Nuclei |
| CWE-94 | Code Injection | Nuclei, Semgrep |
| CWE-91 | XML Injection / XPath Injection | Nuclei |
| CWE-99 | Resource Injection | Nuclei |
| CWE-1021 | Clickjacking | ZAP, Nuclei |

### 2. Subdomain / DNS / Takeover

| CWE | Vulnérabilité | Outil(s) |
|-----|--------------|----------|
| CWE-16 | Subdomain Takeover | dnsReaper, Subdominator |
| CWE-350 | DNS Misconfiguration | dnsReaper |

### 3. SAST / Code Analysis

| CWE | Vulnérabilité | Outil(s) |
|-----|--------------|----------|
| CWE-89 | SQL Injection (source) | Semgrep, CodeQL |
| CWE-78 | Command Injection (source) | Semgrep, CodeQL |
| CWE-79 | XSS (source) | Semgrep, CodeQL |
| CWE-327 | Weak Cryptography | Semgrep, CodeQL |
| CWE-295 | Improper Certificate Validation | Semgrep |
| CWE-502 | Deserialization of Untrusted Data | Semgrep, CodeQL |

### 4. Secrets & Hard-coded Credentials

| CWE | Vulnérabilité | Outil(s) |
|-----|--------------|----------|
| CWE-798 | Hard-coded Credentials | Gitleaks, TruffleHog, detect-secrets |
| CWE-259 | Hard-coded Password | Gitleaks, TruffleHog |
| CWE-256 | Plaintext Storage of Password | Gitleaks, Semgrep |
| CWE-321 | Hard-coded Cryptographic Key | Gitleaks, TruffleHog |
| CWE-312 | Cleartext Storage of Sensitive Info | Gitleaks, Trivy |
| CWE-522 | Insufficiently Protected Credentials | Semgrep |

### 5. Binary Analysis / Memory Vulnerabilities

| CWE | Vulnérabilité | Outil(s) |
|-----|--------------|----------|
| CWE-120/121/122 | Buffer Overflow (stack/heap) | cwe_checker |
| CWE-416 | Use After Free | cwe_checker |
| CWE-415 | Double Free | cwe_checker |
| CWE-476 | NULL Pointer Dereference | cwe_checker |
| CWE-125 | Out-of-bounds Read | cwe_checker |
| CWE-787 | Out-of-bounds Write | cwe_checker |
| CWE-190/191 | Integer Overflow/Underflow | cwe_checker |
| CWE-134 | Uncontrolled Format String | cwe_checker |

### 6. SCA / Vulnerable Dependencies

| CWE | Vulnérabilité | Outil(s) |
|-----|--------------|----------|
| CWE-1395 | Dependency with Known Vulnerability | Trivy, DependencyCheck |
| CWE-1104 | Use of Unmaintained Third-Party Comp. | Trivy |
| CWE-16 | Security Misconfiguration | Trivy |

### 7. LLM / AI Security

| CWE | Vulnérabilité | Outil(s) |
|-----|--------------|----------|
| CWE-1427 | Prompt Injection | garak |
| — | LLM Jailbreak | garak |
| — | Data Exfiltration via LLM | garak |

---

## 🔧 Usage

### Scan complet d'une cible web

```bash
# Scan complet (toutes catégories DAST)
make run TARGET=https://target.example.com

# Scan spécifique par catégorie
make dast TARGET=https://target.example.com       # Web vulns uniquement
make sqli TARGET=https://target.example.com        # SQL Injection uniquement
make secrets REPO=/path/to/repo                    # Secrets dans un repo
make sast CODE=/path/to/source                     # Analyse statique
make binary BIN=/path/to/binary                    # Analyse binaire
make sca IMAGE=myapp:latest                        # Dépendances vulnérables
make llm ENDPOINT=https://api.example.com/chat     # Test LLM
make subdomains DOMAIN=example.com                 # Subdomain takeover
```

### Scan interactif avec ZAP

```bash
make zap-gui    # Lance ZAP avec interface graphique (port 8080)
```

### Générer un rapport unifié

```bash
make report     # Fusionne tous les rapports dans reports/unified-report.json
make summary    # Résumé par CWE
```

### Importer dans DefectDojo

```bash
make defectdojo-import   # Importe tous les résultats
```

---

## 🧰 Outils intégrés

| # | Outil | Version | Catégorie | Licence |
|---|-------|---------|-----------|---------|
| 1 | [Nuclei](https://github.com/projectdiscovery/nuclei) | latest | DAST | MIT |
| 2 | [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates) | latest | DAST | MIT |
| 3 | [OWASP ZAP](https://github.com/zaproxy/zaproxy) | latest | DAST | Apache 2.0 |
| 4 | [SQLMap](https://github.com/sqlmapproject/sqlmap) | latest | SQLi | GPLv2 |
| 5 | [SSTImap](https://github.com/vladko312/SSTImap) | latest | SSTI | MIT |
| 6 | [dnsReaper](https://github.com/punk-security/dnsReaper) | latest | DNS/Takeover | MIT |
| 7 | [Subdominator](https://github.com/Stratus-Security/Subdominator) | latest | DNS/Takeover | MIT |
| 8 | [Semgrep](https://github.com/semgrep/semgrep) | latest | SAST | LGPL 2.1 |
| 9 | [Gitleaks](https://github.com/gitleaks/gitleaks) | latest | Secrets | MIT |
| 10 | [TruffleHog](https://github.com/trufflesecurity/trufflehog) | latest | Secrets | AGPL 3.0 |
| 11 | [cwe_checker](https://github.com/fkie-cad/cwe_checker) | latest | Binary | LGPL 3.0 |
| 12 | [Trivy](https://github.com/aquasecurity/trivy) | latest | SCA | Apache 2.0 |
| 13 | [OWASP DependencyCheck](https://github.com/jeremylong/DependencyCheck) | latest | SCA | Apache 2.0 |
| 14 | [garak](https://github.com/NVIDIA/garak) | latest | LLM | Apache 2.0 |
| 15 | [DefectDojo](https://github.com/DefectDojo/django-DefectDojo) | latest | Reporting | BSD 3 |

---

## 📊 Reporting

Tous les résultats sont stockés dans `reports/` avec un format standardisé :

```
reports/
├── nuclei/scan-2026-03-23.json
├── zap/scan-2026-03-23.json
├── sqlmap/scan-2026-03-23.json
├── semgrep/scan-2026-03-23.json
├── gitleaks/scan-2026-03-23.json
├── trivy/scan-2026-03-23.json
├── cwe-checker/scan-2026-03-23.json
├── garak/scan-2026-03-23.json
└── unified-report.json          # Rapport fusionné (généré par merge-reports.py)
```

Le script `merge-reports.py` normalise tous les formats et produit un JSON unifié
avec déduplication par CWE + severité + URL.

---

## ⚖️ Disclaimer

**Usage exclusif dans le cadre de programmes de Bug Bounty autorisés.**
Vous êtes responsable de l'utilisation de ces outils. Toujours obtenir une
autorisation écrite avant de tester une cible. L'auteur décline toute
responsabilité en cas d'usage non autorisé.

---

## 📜 Licence

MIT — voir [LICENSE](LICENSE)
