# CTF Gap Analysis & Integration Plan

> ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.

> Analyse complète des capacités actuelles vs outils nécessaires pour dominer en CTF.

---

## 📊 Inventaire actuel

### LLM Agent Tools (26)

| # | Tool | Catégorie |
|---|------|-----------|
| 1 | `run_scan` | Orchestration — lance n'importe quel scanner |
| 2 | `shell_exec` | Shell — exécution de commandes |
| 3 | `read_file` | File I/O |
| 4 | `write_file` | File I/O |
| 5 | `list_findings` | Reporting |
| 6 | `generate_report` | Reporting (markdown, YesWeHack, HackerOne, Bugcrowd, Intigriti, Immunefi) |
| 7 | `list_tools` | Découverte |
| 8 | `update_plan` | Planification de tâches |
| 9 | `list_dir` | Navigation FS |
| 10 | `grep_search` | Recherche texte/regex |
| 11 | `file_search` | Recherche fichiers (glob) |
| 12 | `fetch_webpage` | HTTP client |
| 13 | `cdp_exec` | Chrome DevTools Protocol |
| 14 | `browse_page` | Navigation + rendu JS |
| 15 | `workspace_write` | Workspace par conversation |
| 16 | `workspace_read` | Workspace par conversation |
| 17 | `workspace_list` | Workspace par conversation |
| 18 | `vault_scan` | Scan fichiers chiffrés (23 formats) |
| 19 | `vault_extract` | Extraction vault/browser |
| 20 | `password_recover` | Cracking 23 formats |
| 21 | `password_decrypt` | Déchiffrement avec mot de passe connu |
| 22 | `list_recovery_formats` | Liste des formats supportés |
| 23 | `android_adb` | ADB device management |
| 24 | `android_wifi_capture` | Capture WiFi WPA/WPA2 |
| 25 | `android_file_transfer` | Transfert fichiers ADB |
| 26 | `android_shell` | Shell ADB |

### External Scanners (~78 outils)

**Docker-based (35 services):** nuclei (×3 profiles), zap (×4), sqlmap, nikto, ffuf, feroxbuster, nmap, testssl, dalfox, sstimap, crlfuzz, ssrfmap, ppmap, log4j-scan, subfinder, httpx, naabu, katana, amass, dnsx, whatweb, wafw00f, gowitness, graphw00f, clairvoyance, jsluice, cloud-enum, dnsreaper, subdominator, cmseek, theharvester, cherrybomb, interactsh, semgrep, gitleaks, trufflehog, trivy (×2), dependency-check, cwe-checker, cve-bin-tool, dockle, retirejs, garak, jwt-tool, bypass-403, smuggler, checkov, restler, hydra, mitmproxy, masscan

**Python scanners (28):** idor-scanner, auth-bypass, user-enum, notif-inject, redirect-cors, oidc-audit, bypass-403-advanced, ssrf-scanner, xss-scanner, api-discovery, secret-leak, websocket-scanner, cache-deception, slowloris-check, waf-bypass, source-map-scanner, hidden-endpoint-scanner, hateoas-fuzzer, coupon-promo-fuzzer, response-pii-detector, header-classifier, timing-oracle, oauth-flow-scanner, cdp-token-extractor, cdp-checkout-interceptor, cdp-credential-scanner, smart-wordlist, osint-enricher

### Dashboard (16 pages + 13 API groups + 6 LLM providers)

---

## 🔴 Analyse par catégorie CTF

### 1. Web Exploitation — ✅ FORT (95%)

**Couvert :** SQLi, XSS, SSRF, SSTI, CRLF, CORS, IDOR, Auth bypass, JWT, OAuth/OIDC, Cache deception, HTTP smuggling, Prototype pollution, Open redirect, WebSocket, WAF bypass, User enum, GraphQL discovery, API fuzzing, Business logic (timing oracle, coupon fuzzer)

**Manquant :**

| Outil | Catégorie CTF | Priorité | Difficulté |
|-------|---------------|----------|------------|
| `lfi-scanner` | LFI/RFI (CWE-98, 22) — path traversal + php wrappers + log poisoning | HIGH | Moyenne |
| `deser-scanner` | Deserialization (CWE-502) — Java/PHP/Python/Ruby/.NET gadget chains | HIGH | Haute |
| `race-condition` | Race condition (CWE-362) — TOCTOU, double-spend, request-racing | HIGH | Moyenne |
| `graphql-injection` | GraphQL injection — nested queries DoS, batching bypass, introspection abuse | MEDIUM | Basse |
| `xxe-scanner` | XXE (CWE-611) — OOB exfiltration, SSRF via entities, blind XXE | MEDIUM | Moyenne |
| `ssi-scanner` | Server-Side Includes injection (CWE-97) | LOW | Basse |

---

### 2. Cryptography — ⚠️ PARTIEL (40%)

**Couvert :** Password cracking (23 formats chiffrés), WiFi WPA2 handshake, TLS audit (testssl)

**Manquant :**

| Outil | Catégorie CTF | Priorité | Difficulté |
|-------|---------------|----------|------------|
| `crypto-analyzer` | Agent tool: Identification de hash (hashid), détection d'algorithme faible, analyse RSA (factorisation, petit exposant), padding oracle | CRITICAL | Haute |
| `cyberchef` | Encode/decode pipeline: base64, hex, rot13, XOR, URL, HTML entities, JWT decode, custom ciphers | CRITICAL | Moyenne |
| `rsactftool` | Attaques RSA : Wiener, Hastad, Franklin-Reiter, Boneh-Durfee, factordb | HIGH | Moyenne |
| `hash-cracker` | John the Ripper / Hashcat wrapper — cracking offline de hashes (MD5, SHA, bcrypt, etc.) | HIGH | Basse |
| `padding-oracle` | PadBuster — attaque oracle de padding CBC | MEDIUM | Basse |

---

### 3. Forensics — 🔴 FAIBLE (15%)

**Couvert :** Scan fichiers chiffrés (vault_scan), extraction navigateur (vault_extract)

**Manquant :**

| Outil | Catégorie CTF | Priorité | Difficulté |
|-------|---------------|----------|------------|
| `steg-analyzer` | Stéganographie : steghide, zsteg, stegsolve, LSB analysis, binwalk, foremost | CRITICAL | Moyenne |
| `pcap-analyzer` | Analyse PCAP/PCAPNG : tshark/pyshark, extraction credentials, DNS exfil, HTTP objects, streams | CRITICAL | Moyenne |
| `forensic-imager` | Forensique disque/mémoire : volatility3 (RAM dump), strings, exiftool (metadata), file carving | HIGH | Haute |
| `log-analyzer` | Analyse de logs : parsing auth.log, access.log, détection d'activités suspectes, timeline | HIGH | Moyenne |
| `metadata-extractor` | exiftool wrapper — extraction metadata (EXIF, XMP, IPTC) depuis images, PDF, documents | MEDIUM | Basse |
| `file-identifier` | file + TrID + binwalk — identification format, magic bytes, fichiers embeddés | MEDIUM | Basse |

---

### 4. Reverse Engineering — 🔴 TRÈS FAIBLE (10%)

**Couvert :** cwe-checker (analyse de vulnérabilités binaires)

**Manquant :**

| Outil | Catégorie CTF | Priorité | Difficulté |
|-------|---------------|----------|------------|
| `disasm-analyzer` | Désassemblage : radare2/rizin CLI — analyse binaire, strings, cross-refs, CFG | CRITICAL | Haute |
| `decompiler` | Décompilation : Ghidra headless — décompilation C, analyse de fonctions, renommage | CRITICAL | Haute |
| `apk-analyzer` | Android RE : apktool + jadx — décompilation APK, analyse manifest, extraction assets | HIGH | Moyenne |
| `dotnet-decompiler` | .NET RE : ILSpy CLI — décompilation DLL/EXE C# | MEDIUM | Basse |
| `java-decompiler` | Java RE : jadx / CFR — décompilation JAR, analyse de classes | MEDIUM | Basse |

---

### 5. Binary Exploitation (Pwn) — 🔴 ABSENT (0%)

**Couvert :** Rien (cwe-checker fait de l'analyse statique, pas de l'exploitation)

**Manquant :**

| Outil | Catégorie CTF | Priorité | Difficulté |
|-------|---------------|----------|------------|
| `pwn-toolkit` | Agent tool: checksec, ROPgadget, one_gadget, patchelf, seccomp-tools | CRITICAL | Haute |
| `shellcode-gen` | Génération shellcode : encodage, NOP sleds, polymorphisme, msfvenom wrapper | HIGH | Moyenne |
| `format-string` | Format string exploitation helper | MEDIUM | Basse |
| `heap-analyzer` | Heap exploitation assistant : bins, chunks, tcache, fastbin | MEDIUM | Haute |

---

### 6. OSINT — ⚠️ PARTIEL (50%)

**Couvert :** theHarvester, subfinder, amass, httpx, naabu, katana, osint-enricher, DNS tools

**Manquant :**

| Outil | Catégorie CTF | Priorité | Difficulté |
|-------|---------------|----------|------------|
| `shodan-recon` | Shodan/Censys API — recherche IP, ports, bannières, vulnérabilités, IoT | HIGH | Basse |
| `google-dorker` | Google Dorks automation — inurl, intitle, filetype, site, cache | MEDIUM | Basse |
| `social-osint` | Sherlock / Holehe — recherche username cross-platform, email verification | MEDIUM | Basse |
| `whois-enricher` | WHOIS enrichi + rapprochement domaines, registrar history | LOW | Basse |

---

### 7. Network — ⚠️ PARTIEL (45%)

**Couvert :** Nmap, mitmproxy, masscan, ADB WiFi capture, Android bridge

**Manquant :**

| Outil | Catégorie CTF | Priorité | Difficulté |
|-------|---------------|----------|------------|
| `packet-crafter` | Scapy wrapper — crafting de paquets, fuzzing réseau, sniffing | HIGH | Moyenne |
| `responder-tool` | LLMNR/NBT-NS/MDNS poisoning, credential capture | MEDIUM | Moyenne |
| `impacket-tools` | SMB relay, secretsdump, psexec, wmiexec, kerberoasting | MEDIUM | Haute |

---

### 8. Privilege Escalation — 🔴 ABSENT (0%)

**Manquant :**

| Outil | Catégorie CTF | Priorité | Difficulté |
|-------|---------------|----------|------------|
| `privesc-scanner` | LinPEAS + WinPEAS + linux-exploit-suggester — enum automatisée | CRITICAL | Basse |
| `gtfobins-lookup` | GTFOBins/LOLBAS/WADComs lookup — exploitation sudo/SUID/capabilities | HIGH | Basse |

---

### 9. Misc CTF — ⚠️ PARTIEL (30%)

**Couvert :** Shell (encodage base64, xxd, python crypto), garak (LLM prompt injection)

**Manquant :**

| Outil | Catégorie CTF | Priorité | Difficulté |
|-------|---------------|----------|------------|
| `encoder-decoder` | CyberChef-style transformations: base32/58/64/85, hex, ROT, XOR, Vigenère, URL, HTML, Unicode | HIGH | Moyenne |
| `qr-reader` | QR code / barcode reader + generator (zbarimg) | LOW | Basse |

---

## 📈 Matrice de couverture CTF

| Catégorie | Score | Priorité gaps |
|-----------|-------|---------------|
| Web Exploitation | ✅ 95% | 3 HIGH |
| Cryptography | ⚠️ 40% | 2 CRITICAL, 2 HIGH |
| Forensics | 🔴 15% | 2 CRITICAL, 2 HIGH |
| Reverse Engineering | 🔴 10% | 2 CRITICAL, 2 HIGH |
| Pwn (Binary Exploitation) | 🔴 0% | 1 CRITICAL, 1 HIGH |
| OSINT | ⚠️ 50% | 1 HIGH |
| Network | ⚠️ 45% | 1 HIGH |
| Privilege Escalation | 🔴 0% | 1 CRITICAL, 1 HIGH |
| Misc | ⚠️ 30% | 1 HIGH |

**Score global CTF : ~38%** — Très fort en web, quasi absent en forensics/RE/pwn.

---

## 🏗️ Plan d'intégration — 5 Sprints

### Sprint 1 — CRITICAL (Forensics + Crypto) — 5 nouveaux outils

**Objectif :** Couvrir les 2 catégories les plus demandées en CTF après le web.

#### 1.1 — `steg_analyzer.py` (Python scanner)
- **Fonction :** Détection et extraction stéganographique
- **Techniques :** LSB (PIL), zsteg (Ruby gem wrapper), steghide, binwalk (fichiers embeddés), foremost (file carving), strings, exiftool (metadata)
- **Intégration :**
  - `tools/python-scanners/steg_analyzer.py`
  - Docker: image avec steghide + zsteg + binwalk + foremost pré-installés
  - `tools-data.ts`: groupe `forensics`, profile `forensics`
  - Dashboard: page `/forensics` avec upload d'images + résultats visuels
  - Agent tool: non (utilise `run_scan` avec `tool=steg-analyzer`)

#### 1.2 — `pcap_analyzer.py` (Python scanner)
- **Fonction :** Analyse de captures réseau
- **Techniques :** pyshark/tshark parsing, extraction HTTP objects, DNS exfiltration detection, credential sniffing (FTP, Telnet, HTTP Basic), stream reassembly, statistiques protocoles
- **Intégration :**
  - `tools/python-scanners/pcap_analyzer.py`
  - Utilise tshark (déjà dans la plupart des images réseau)
  - Synergie avec `android_wifi_capture` → le PCAP capturé passe directement dans `pcap_analyzer`

#### 1.3 — `crypto_analyzer.py` (NOUVEL agent tool)
- **Fonction :** Boîte à outils crypto pour CTF
- **Sous-commandes :**
  - `identify` — Identification de hash (MD5, SHA1/256/512, bcrypt, base64, hex, custom)
  - `rsa_attack` — Attaques RSA (factordb, Wiener, Hastad, petit exposant, common factor)
  - `xor_crack` — XOR brute-force (single byte, known-plaintext)
  - `decode_chain` — Décodage chaîné (base64→hex→rot13→...)
  - `padding_oracle` — Attaque padding oracle CBC automatisée
  - `frequency` — Analyse fréquentielle (substitution ciphers)
- **Intégration :**
  - `llm/agent_tools.py` → nouveau `ToolDefinition("crypto_analyze", ...)`
  - `tools/python-scanners/crypto_analyzer.py` pour la logique
  - Dépendances : `pycryptodome`, `sympy` (factorisation), `requests` (factordb API)

#### 1.4 — `encoder_decoder.py` (NOUVEL agent tool)
- **Fonction :** CyberChef-style encode/decode
- **Opérations :** base16/32/58/64/85, hex, ROT1-25, XOR, URL encode/decode, HTML entities, JWT decode, Unicode escape, Vigenère, affine cipher, binary/octal, morse code, brainfuck, ASCII art
- **Intégration :**
  - `llm/agent_tools.py` → nouveau `ToolDefinition("encode_decode", ...)`
  - Logic inline dans `agent_tools.py` (pas de dépendances externes, Python stdlib)
  - Chaînable : `operations: ["base64_decode", "hex_decode", "xor:0x42"]`

#### 1.5 — `forensic_toolkit.py` (Python scanner)
- **Fonction :** Ensemble forensique basique
- **Techniques :** volatility3 (profil mémoire, pslist, netscan, filescan, hashdump), exiftool (metadata), file/TrID (identification format), strings extraction, foremost
- **Intégration :**
  - `tools/python-scanners/forensic_toolkit.py`
  - Docker : image avec volatility3 + sleuthkit + exiftool
  - Profile `forensics` dans tools-data.ts

---

### Sprint 2 — CRITICAL (Reverse Engineering + Pwn) — 4 nouveaux outils

#### 2.1 — `disasm_analyzer.py` (NOUVEL agent tool)
- **Fonction :** Analyse binaire automatisée
- **Sous-commandes :**
  - `info` — file, checksec, readelf, sections, symbols, strings
  - `disasm` — radare2 `pdf @ main` / `pdf @ sym.functionName`
  - `decompile` — Ghidra headless décompilation vers pseudo-C
  - `xrefs` — Cross-references, call graph
  - `strings` — Strings intelligents avec contexte (pas juste `strings`)
  - `patch` — Patch binaire (NOP, JMP, valeur)
- **Intégration :**
  - `llm/agent_tools.py` → nouveau `ToolDefinition("binary_analyze", ...)`
  - Docker : image avec radare2 + Ghidra headless + binutils
  - Utilise r2pipe pour la communication avec radare2

#### 2.2 — `pwn_toolkit.py` (NOUVEL agent tool)
- **Fonction :** Assistant exploitation binaire
- **Sous-commandes :**
  - `checksec` — Protections (NX, PIE, RELRO, stack canary, FORTIFY)
  - `ropgadget` — Recherche de gadgets ROP/JOP
  - `one_gadget` — Recherche de one-gadget dans libc
  - `shellcode` — Génération shellcode (x86/x64/ARM, encodé ou non)
  - `pattern` — Pattern cyclic create/offset (De Bruijn)
  - `libc_search` — Recherche de libc par leak d'adresses (libc.rip)
- **Intégration :**
  - `llm/agent_tools.py` → nouveau `ToolDefinition("pwn_toolkit", ...)`
  - Docker : image avec pwntools, ROPgadget, one_gadget, seccomp-tools
  - Complémentaire à `binary_analyze` (analyse → exploitation)

#### 2.3 — `apk_analyzer.py` (Python scanner)
- **Fonction :** Reverse engineering Android
- **Techniques :** apktool (décompilation APK), jadx (Java decompilation), analyse AndroidManifest.xml, extraction hardcoded secrets, certification pinning detection, exported components audit
- **Intégration :**
  - `tools/python-scanners/apk_analyzer.py`
  - Synergie avec `android_adb` + `android_file_transfer` (pull APK → analyze)
  - Docker : image avec apktool + jadx + dex2jar

#### 2.4 — `privesc_scanner.py` (NOUVEL agent tool)
- **Fonction :** Énumération privilege escalation
- **Sous-commandes :**
  - `linux_enum` — SUID, capabilities, cron, writable paths, sudo -l, kernel version
  - `windows_enum` — Services, scheduled tasks, unquoted paths, always-elevated
  - `gtfobins` — Lookup GTFOBins/LOLBAS/WADComs par binaire
  - `suggest` — Suggest exploits par kernel/OS version
- **Intégration :**
  - `llm/agent_tools.py` → nouveau `ToolDefinition("privesc_scan", ...)`
  - Peut s'exécuter localement ou via SSH/ADB sur une cible
  - Base de données GTFOBins intégrée (JSON offline)

---

### Sprint 3 — HIGH (Web avancé + OSINT) — 5 nouveaux outils

#### 3.1 — `lfi_scanner.py` (Python scanner)
- **Techniques :** Path traversal (../../etc/passwd), PHP wrappers (php://filter, php://input, data://), log poisoning, /proc/self, null byte, double encoding
- **Intégration :** `tools/python-scanners/lfi_scanner.py`, profile `python-scanners`

#### 3.2 — `deser_scanner.py` (Python scanner)
- **Techniques :** Java (ysoserial payloads detection), PHP (unserialize detection), Python (pickle), .NET (BinaryFormatter, TypeNameHandling), Ruby (Marshal.load)
- **Intégration :** `tools/python-scanners/deser_scanner.py`, profile `python-scanners`

#### 3.3 — `race_condition.py` (Python scanner)
- **Techniques :** Parallel requests via asyncio, TOCTOU detection, double-submit, limit bypass (coupon reuse, balance race), file race
- **Intégration :** `tools/python-scanners/race_condition.py`, profile `python-scanners`

#### 3.4 — `shodan_recon.py` (NOUVEL agent tool)
- **Fonction :** OSINT via Shodan/Censys
- **Sous-commandes :** `ip_lookup`, `domain_search`, `cve_search`, `port_search`, `banner_search`
- **Intégration :** `llm/agent_tools.py`, requiert `SHODAN_API_KEY` env

#### 3.5 — `hash_cracker.py` (Python scanner)
- **Techniques :** John the Ripper + Hashcat wrapper, auto-détection du format, wordlists intégrées (rockyou, SecLists)
- **Intégration :** Docker avec john + hashcat, `tools/python-scanners/hash_cracker.py`

---

### Sprint 4 — MEDIUM (Network + Misc) — 3 nouveaux outils

#### 4.1 — `packet_crafter.py` (Python scanner)  
- **Techniques :** Scapy wrapper — crafting TCP/UDP/ICMP, SYN flood test, DNS spoofing test, ARP scanning
- **Intégration :** `tools/python-scanners/packet_crafter.py`

#### 4.2 — `log_analyzer.py` (Python scanner)
- **Techniques :** Parsing multi-format (auth.log, access.log, Windows Event Logs, syslog), détection brute-force, timeline reconstruction, anomaly detection
- **Intégration :** `tools/python-scanners/log_analyzer.py`

#### 4.3 — `xxe_scanner.py` (Python scanner)
- **Techniques :** OOB XXE, blind XXE via SSRF, entity expansion DoS, XML parameter entities, SOAP XXE
- **Intégration :** `tools/python-scanners/xxe_scanner.py`

---

### Sprint 5 — Dashboard + Documentation — 0 nouveaux outils

#### 5.1 — Nouvelle page `/forensics`
- Upload de fichiers (images, PCAP, binaires, RAM dumps)
- Résultats avec visualisation (hex view, image steg layers, PCAP streams)
- Intégration avec `steg_analyzer`, `pcap_analyzer`, `forensic_toolkit`

#### 5.2 — Nouvelle page `/reversing`
- Upload de binaire
- Affichage désassemblage + décompilation
- Checksec + protections visuelles
- Intégration avec `binary_analyze`, `pwn_toolkit`, `apk_analyzer`

#### 5.3 — Mise à jour page `/tools`
- Ajout des nouvelles catégories (Forensics, RE, Pwn, Crypto)
- Badges de couverture CTF par catégorie

#### 5.4 — Mise à jour docs
- README.md : tous les nouveaux outils
- ARCHITECTURE.md : nouvelles pages, nouvelles API routes, nouveaux agent tools

---

## 📅 Résumé des livrables

| Sprint | Outils | Agent tools | Pages | Score CTF |
|--------|--------|-------------|-------|-----------|
| Actuel | 78 scanners + 26 agent | 26 | 16 | ~38% |
| Sprint 1 | +5 | +2 (`crypto_analyze`, `encode_decode`) | — | ~55% |
| Sprint 2 | +4 | +3 (`binary_analyze`, `pwn_toolkit`, `privesc_scan`) | — | ~68% |
| Sprint 3 | +5 | +1 (`shodan_recon`) | — | ~80% |
| Sprint 4 | +3 | — | — | ~88% |
| Sprint 5 | — | — | +2 (`/forensics`, `/reversing`) | ~90% |
| **Total** | **95 scanners + 32 agent** | **32** | **18** | **~90%** |

---

## 🎯 Priorisation CRITICAL — Top 8 manquants

1. **`crypto_analyzer`** — Agent tool crypto CTF (hash ID, RSA attacks, XOR, padding oracle)
2. **`steg_analyzer`** — Stéganographie (LSB, steghide, binwalk, foremost)
3. **`pcap_analyzer`** — Analyse PCAP (tshark, stream extraction, credential sniffing)
4. **`encoder_decoder`** — CyberChef-like (encode/decode chains)
5. **`binary_analyze`** — Désassemblage + décompilation (radare2, Ghidra headless)
6. **`pwn_toolkit`** — Exploitation binaire (checksec, ROP, shellcode, pattern)
7. **`privesc_scanner`** — LinPEAS/WinPEAS + GTFOBins
8. **`forensic_toolkit`** — Volatility3 + exiftool + file identification

Ces 8 outils comblent **82% du gap CTF restant**.
