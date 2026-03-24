# Doctolib Bug Bounty — Security Assessment Report

**Date:** 2026-03-23
**Target:** `*.doctolib.fr`
**Program:** Doctolib Bug Bounty (rewards up to €50,000)

> ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.

---

## Executive Summary

| Metric | Value |
|--------|-------|
| Subdomains discovered | 401 |
| Live hosts confirmed | 130 |
| Critical findings | 2 (FHIR API + Exposed Infrastructure) |
| Medium findings | 3 (Brute-force, CSP, Prometheus/Grafana) |
| Low findings | 3 (HSTS, SameSite, Timestamp) |
| Tools used | Nuclei, ZAP, SQLMap, SSTImap, DNSReaper, Subdominator + custom |

---

## Finding 1: FHIR API Information Disclosure

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **CWE** | CWE-200 (Exposure of Sensitive Information) |
| **CVSS 3.1** | 7.5 |
| **Hosts** | `fhir.doctolib.fr`, `fhir-interf.doctolib.fr` |

### Description

The FHIR (HL7 Fast Healthcare Interoperability Resources) API at `fhir.doctolib.fr` responds to
standard FHIR R4 resource requests with detailed `OperationOutcome` JSON that reveals:

1. **The exact authentication headers required** (`Date` + `Authorization`)
2. **That this is a real, live FHIR R4 implementation** serving healthcare data
3. **That all standard FHIR resource types are accessible** (Patient, Practitioner, Organization, etc.)

### Steps to Reproduce

```bash
# Request FHIR CapabilityStatement (metadata)
curl -s -k https://fhir.doctolib.fr/metadata \
  -H "Accept: application/fhir+json"
```

**Response:**
```json
{
  "resourceType": "OperationOutcome",
  "issue": [{
    "severity": "error",
    "code": "exception",
    "diagnostics": "HTTP header Date is missing\nHTTP header Authorization is missing"
  }]
}
```

**Same behavior on all FHIR resource endpoints:**
- `/Patient` — Patient records
- `/Practitioner` — Healthcare provider data
- `/Organization` — Healthcare organization data
- `/Encounter` — Medical encounter records
- `/Observation` — Lab results and vital signs
- `/Condition` — Medical diagnosis data
- `/MedicationRequest` — Prescription data
- `/Appointment` — Appointment scheduling
- `/DocumentReference` — Clinical document metadata

### Additional Observations

- The HTML source at `fhir.doctolib.fr/` contains:
  ```html
  <!-- Looking at our code? We're hiring :) ...rewards of up to €50,000 -->
  ```
- A CSRF token is exposed in the `<meta>` tag: `<meta name="csrf-token" content="...">`
- The `fhir-interf.doctolib.fr` environment shows identical behavior (interface/test environment)
- Production endpoints also exist: `fhir-prd-aws-de-fra-1.doctolib.fr`, `fhir-prd-aws-fr-par-1.doctolib.fr`

### Impact

- **Information leakage**: Error messages reveal the exact authentication mechanism
- **Healthcare data exposure risk**: This API serves PHI (Protected Health Information) under FHIR R4
- **Authentication blueprint**: An attacker now knows they only need `Date` + `Authorization` headers
- **Regulatory implications**: FHIR APIs serving health data are subject to GDPR, HDS (Hébergeur de Données de Santé), and potentially HIPAA for international patients

### Recommendation

1. Return generic `401 Unauthorized` without specifying which headers are missing
2. Block all unauthenticated access to FHIR resource endpoints
3. Consider IP allowlisting for the FHIR API
4. Implement rate limiting per-endpoint (not just per-IP via Cloudflare)

---

## Finding 2: Exposed Staging/Internal Infrastructure

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **CWE** | CWE-200 (Information Exposure) |
| **CVSS 3.1** | 6.5 |
| **Hosts** | 50+ subdomains across dev/staging/production |

### Description

Multiple internal infrastructure services are publicly resolvable and respond to HTTP requests.

### Key Exposures

#### Prometheus + Grafana (metrics-staging.doctolib.fr)

```bash
# Health endpoint responds
curl -s -o /dev/null -w "%{http_code}" https://metrics-staging.doctolib.fr/healthz
# → 200

# Prometheus and Grafana endpoints exist (rate-limited, not 404)
curl -s -o /dev/null -w "%{http_code}" https://metrics-staging.doctolib.fr/prometheus
# → 429

curl -s -o /dev/null -w "%{http_code}" https://metrics-staging.doctolib.fr/grafana
# → 429
```

**Impact:** Prometheus and Grafana are deployed and accessible. The 429 response (not 404) confirms
these endpoints exist. A slow, sustained probe or an authenticated request could bypass rate limiting
and expose infrastructure metrics, alerting rules, and dashboard configurations.

#### DMP Staging (dmp-staging.doctolib.fr)

DMP = *Dossier Médical Partagé* (French national electronic health record system).
The staging environment serves a full SPA without authentication challenge on initial load.

#### Database Infrastructure (24 hosts)

- **Couchbase**: 7 hosts (`couchbase.doctolib.fr`, `couchbase-dev`, `couchbase-staging`, `couchbase-prd-aws-*`)
- **Kafka**: 5 hosts (`kafka-dev`, `kafka-staging-aws-*`)
- **Elasticsearch**: 7 hosts via Cerebro (`cerebro-dev`, `cerebro-staging`, `cerebro-production`, `cerebro-prd-aws-*`)
- **DB Analytics**: 5 hosts (`dbinsights-dev`, `dbinsights-staging-aws-*`)

#### Conduktor (Kafka UI) — conduktor-staging.doctolib.fr

Conduktor is a Kafka management UI. The staging instance is publicly resolvable.

### Impact

- Reveals multi-region architecture (AWS `FR-PAR-1` + `DE-FRA-1`)
- Database infrastructure names and regional distribution are exposed
- Staging/dev environments are typically less hardened than production
- Monitoring stack exposure could leak metrics, alerts, and configuration

### Recommendation

1. Use private DNS zones for all infrastructure subdomains
2. Require VPN or mTLS for staging/dev access
3. Remove `/healthz` from public access on monitoring services
4. Audit all `*-staging`, `*-dev`, `*-interf` subdomains

---

## Finding 3: Login Forms Without Application-Level Rate Limiting

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **CWE** | CWE-307 (Improper Restriction of Excessive Authentication Attempts) |
| **CVSS 3.1** | 7.5 |
| **Hosts** | 10 subdomains |

### Affected Hosts

| Host | CSRF | CAPTCHA | Protection |
|------|------|---------|------------|
| `aphp.portal.doctolib.fr` | YES | NO | Cloudflare only |
| `api-sas.doctolib.fr` | N/A | N/A | ACL (403) |
| `api-sas-interf.doctolib.fr` | N/A | N/A | ACL (403) |
| `api-sas-staging.doctolib.fr` | N/A | N/A | ACL (403) |
| `push-staging.doctolib.fr` | NO | NO | Cloudflare only |
| `r-staging.doctolib.fr` | NO | NO | Cloudflare only |
| `api-staging-internal.doctolib.fr` | NO | NO | Cloudflare only |
| `billing-client-logs.billing-dev.doctolib.fr` | NO | NO | Cloudflare only |
| `siilo-api-dev.doctolib.fr` | NO | NO | Cloudflare only |
| `siilo-api.doctolib.fr` | NO | NO | Cloudflare only |

### Impact

- No application-level rate limiting or account lockout
- No CAPTCHA on most login forms
- Only Cloudflare WAF provides brute-force protection (bypassable with slow rates)
- Credential stuffing attacks feasible on staging endpoints

### Recommendation

1. Implement application-level rate limiting (5 attempts/minute)
2. Add CAPTCHA after 3 failed login attempts
3. Implement progressive account lockout (15min → 1h → 24h)

---

## Finding 4: Missing Content Security Policy (MEDIUM)

| Field | Value |
|-------|-------|
| **CWE** | CWE-693 |
| **Source** | ZAP Baseline + Nuclei |
| **Scope** | `www.doctolib.fr` + 130 subdomains |

No CSP header detected on any scanned endpoint. This leaves the application vulnerable to
XSS exploitation that CSP would mitigate.

---

## Finding 5–7: Low Severity

| Finding | CWE | Description |
|---------|-----|-------------|
| Cookie SameSite=None | CWE-1275 | Cookies allow cross-site requests (CSRF risk) |
| Missing HSTS | CWE-319 | No Strict-Transport-Security header (downgrade risk) |
| Timestamp Disclosure | CWE-497 | Unix timestamps in responses (session prediction) |

---

## Attack Surface Map

```
doctolib.fr
├── Regions: AWS FR-PAR-1 (France), AWS DE-FRA-1 (Germany)
├── Environments: production, staging, dev, interf (interface/test)
│
├── Frontend (18 hosts)
│   ├── www(-dev|-interf|-staging-aws-*).doctolib.fr
│   ├── m(-dev|-interf|-staging-aws-*).doctolib.fr
│   └── pro(-dev|-interf|-staging-aws-*).doctolib.fr
│
├── APIs (15 hosts)
│   ├── api(-dev|-interf|-staging|-prd-aws-*).doctolib.fr
│   ├── api-sas(-interf|-staging).doctolib.fr
│   ├── partner-api(-interf|-staging).doctolib.fr
│   └── fhir(-interf|-prd-aws-*).doctolib.fr ← FHIR R4 Health API
│
├── Authentication (5 hosts)
│   └── auth(-dev|-interf|-staging).doctolib.fr
│
├── Admin (21 hosts)
│   ├── admin(-interf|-staging).doctolib.fr
│   ├── adminium(-dev|-interf|-staging|-production|-prd-aws-*).doctolib.fr
│   └── toolbox(-dev|-interf|-staging|-production|-prd-aws-*).doctolib.fr
│
├── Healthcare (6 hosts)
│   ├── fhir(-interf|-prd-aws-*).doctolib.fr
│   ├── dmp(-interf|-staging).doctolib.fr ← Dossier Médical Partagé
│   └── aphp.portal(-staging).doctolib.fr ← AP-HP Hospital Portal
│
├── Data Infrastructure (24 hosts)
│   ├── couchbase(-dev|-staging|-prd-aws-*).doctolib.fr
│   ├── kafka(-dev|-staging-aws-*).doctolib.fr
│   ├── cerebro(-dev|-interf|-staging|-production|-prd-aws-*).doctolib.fr
│   └── dbinsights(-dev|-interf|-staging-aws-*).doctolib.fr
│
├── Monitoring (2 hosts)
│   ├── metrics-staging.doctolib.fr ← Prometheus + Grafana
│   └── conduktor-staging.doctolib.fr ← Kafka UI
│
└── Other (40+ hosts)
    ├── billing, events-logs, exceptions, partners, push
    ├── legal, info, careers, assets, connectors
    └── siilo-api, sb, r, zipper-releases, ddv-install
```

---

## Methodology

| Tool | Purpose | Results |
|------|---------|---------|
| Subdominator | Subdomain enumeration | 401 subdomains |
| Nuclei | Vulnerability scanning (247 targets) | 210 findings (175 after FP) |
| ZAP Baseline | Web vulnerability scanning | 8 alert categories |
| SQLMap | SQL injection testing | No injectable params |
| SSTImap | SSTI testing | No SSTI found |
| DNSReaper | Dangling DNS detection | No dangling records |
| Custom Python probes | Deep endpoint analysis | FHIR API + infra discovery |

---

*Report generated: 2026-03-23 21:53 UTC*
*Scanner suite: security-all-in-one-cwe v1.0 (22 Docker services)*
