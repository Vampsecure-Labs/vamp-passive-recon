<!-- © VampSecure Studios — VampSecure Labs Security Research Division -->
<p align="center">
  <img src="https://img.shields.io/badge/version-1.2.0-crimson?style=flat-square" />
  <img src="https://img.shields.io/badge/python-3.11+-blue?style=flat-square&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/async-aiohttp-teal?style=flat-square" />
  <img src="https://img.shields.io/badge/VampSecure_Labs-Security_Research-8b0000?style=flat-square" />
  <img src="https://github.com/Vampsecure-Labs/vamp-passive-recon/actions/workflows/ci.yml/badge.svg" alt="CI"/>
</p>

<h1 align="center">vamp-passive-recon</h1>
<p align="center"><em>Passive Recon &amp; Attack Surface Mapping Engine — VampSecure Labs</em></p>

---

## Overview

**vamp-passive-recon** is a modular passive reconnaissance tool that discovers subdomains, maps the external attack surface, and audits HTTP security headers — entirely through open-source intelligence sources, without sending a single packet directly to the target during enumeration.

The engine queries **eight OSINT sources** concurrently, deduplicates and validates results, and runs an Attack Surface Management (ASM) analysis phase that examines Certificate Transparency logs, GitHub dorks, and exposed infrastructure metadata. An optional Shodan enrichment phase appends service fingerprints and known CVEs to live hosts.

---

## Features

- Eight concurrent OSINT sources: crt.sh, AlienVault OTX Passive DNS, HackerTarget, Wayback Machine, AnubisDB, urlscan.io, RapidDNS, BufferOver
- ASM phase: Certificate Transparency analysis, GitHub dork enumeration (requires `GITHUB_TOKEN`), exposed infrastructure detection
- HTTP security header audit per active host: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Permissions-Policy, Server information leakage, Set-Cookie flag analysis
- Optional Shodan enrichment for service fingerprinting and CVE correlation
- Scope enforcement via `--allowed-domains` to restrict analysis to authorized targets
- Subdomain export for use as input to other VSL tools (e.g., vamp-subdomain-takeover)
- Three output formats: Rich console, JSON, HTML

---

## Requirements

```
Python 3.11+
aiohttp >= 3.9.0
rich >= 13.7.0
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Installation


```bash
pip install vamp-passive-recon
# o con Homebrew:
brew install vampsecure-labs/labs/vamp-passive-recon
```

```bash
git clone https://github.com/belky-me/vamp-passive-recon.git
cd vamp-passive-recon
pip install -r requirements.txt
```

---

## Configuration

| Variable | Purpose | Required |
|----------|---------|----------|
| `OTX_API_KEY` | AlienVault OTX Passive DNS enrichment | Optional — increases OTX data volume |
| `GITHUB_TOKEN` | GitHub dork queries in the ASM phase | Optional — required for GitHub ASM |

```bash
export OTX_API_KEY=your_otx_key
export GITHUB_TOKEN=your_github_token
```

---

## Usage

```
python vamp_passive_recon.py -d DOMAIN [OPTIONS]

Required:
  -d, --domain DOMAIN            Target apex domain to enumerate

Scope:
      --allowed-domains DOM,...  Comma-separated list of domains to include in header analysis
                                 (default: target domain only)

Analysis control:
      --no-headers               Skip the HTTP security header audit phase
      --no-asm                   Skip the ASM (attack surface mapping) phase
      --max-hosts N              Maximum hosts to probe in header analysis (default: 15)
      --concurrency N            Concurrent OSINT source queries (default: 5)

Enrichment:
      --shodan-key API_KEY       Shodan API key for service fingerprinting

Output:
      --json FILE                Write findings to JSON
      --html FILE                Generate standalone HTML report
      --subs-out FILE            Write subdomain list only (one per line)
      --quiet                    Suppress console output (useful for piping)
```

---

## Examples

Basic passive recon of a target domain:

```bash
python vamp_passive_recon.py -d example.com
```

Full recon with ASM phase and HTML report:

```bash
python vamp_passive_recon.py -d example.com --json recon.json --html report.html
```

Export subdomain list as input for the subdomain takeover scanner:

```bash
python vamp_passive_recon.py -d example.com --subs-out subdomains.txt --no-headers --no-asm
python vamp_subdomain_takeover.py -d example.com -f subdomains.txt
```

Recon with Shodan enrichment and restricted header analysis scope:

```bash
python vamp_passive_recon.py -d example.com \
  --allowed-domains example.com,api.example.com \
  --shodan-key YOUR_KEY \
  --html full_report.html
```

---

## Output Formats

| Format | How to enable | Description |
|--------|---------------|-------------|
| Console | Default | Rich panels: subdomain table, ASM findings, header audit summary |
| JSON | `--json FILE` | All findings with source attribution, header scores, and ASM data |
| HTML | `--html FILE` | Standalone report with tabbed sections for each analysis phase |
| Subdomains | `--subs-out FILE` | Plain text subdomain list for pipeline chaining |

---

## Exit Codes

| Code | Meaning | CI/CD usage |
|------|---------|-------------|
| `0` | Recon complete — no high-severity header or ASM findings | Pass gate |
| `1` | Moderate findings (missing security headers, minor exposure) | Review recommended |
| `2` | High-severity ASM findings or critical header misconfigurations | Fail gate |

---

## Analysis Phases

| Phase | Sources / Actions |
|-------|------------------|
| 1. Subdomain enumeration | crt.sh, OTX, HackerTarget, Wayback, AnubisDB, urlscan.io, RapidDNS, BufferOver |
| 2. ASM analysis | Certificate Transparency deep scan, GitHub dorks, exposed service detection |
| 3. Header audit | HEAD request per active host — security header presence and configuration |
| 4. Shodan enrichment | Port scan results, service banners, CVE annotations (optional) |

---

## Sample Output

```bash
$ python vamp_passive_recon.py -d example.com \
    --allowed-domains example.com,api.example.com \
    --shodan-key YOUR_KEY \
    --json recon.json --html report.html
```

```
╭──────────────────────────────────────────────────────────────────────────────╮
│  vamp-passive-recon v1.2.0 · VampSecure Labs Security Research Division      │
│  Target: example.com  ·  Shodan: enabled  ·  Concurrencia: 5                │
╰──────────────────────────────────────────────────────────────────────────────╯

Fase 1 — Enumeración de subdominios
  Consultando: crt.sh, OTX, HackerTarget, Wayback, AnubisDB, urlscan.io, RapidDNS, BufferOver
  ✓ 47 subdominios descubiertos, 38 únicos tras deduplicación

Fase 2 — ASM (Attack Surface Mapping)
  → Certificate Transparency: 12 certificados analizados, 3 dominios adicionales
  → GitHub dorks: 1 resultado relevante — posible fichero .env expuesto en repo público
  → Infraestructura expuesta: 2 hosts con banner de servicio interno

Fase 3 — Auditoría de headers HTTP (15 hosts activos)
  ✓ 15 hosts auditados
  ⚠ CSP ausente:              9/15 hosts
  ⚠ HSTS ausente:             4/15 hosts
  ⚠ X-Frame-Options ausente: 11/15 hosts
  ⚠ Server header expuesto:   7/15 hosts (nginx/1.18.0)

Fase 4 — Enriquecimiento Shodan
  → 8 hosts con datos Shodan
  → 3 CVEs correlacionadas en hosts activos

╭──────────────────────────────── Hallazgos ASM ──────────────────────────────╮
│ Tipo          │ Sev.     │ Descripción                                       │
│ GitHub dork   │ 🔴 HIGH  │ Repo público con posible fichero .env             │
│ Banner leak   │ 🟠 MED   │ 2 hosts exponen banner de servicio interno        │
│ CVE correlada │ 🟠 MED   │ CVE-2021-44228 detectada en 192.168.1.10        │
│ Header audit  │ 🔵 LOW   │ CSP ausente en 9/15 hosts de example.com         │
╰─────────────────────────────────────────────────────────────────────────────╯

Subdominios exportados → recon.json
Informe HTML         → report.html
Total: 47 subdominios · 4 findings · 3 CVEs correlacionadas
```

---

## Why vamp-passive-recon vs. SpiderFoot · theHarvester · Maltego

| Capacidad | vamp-passive-recon | SpiderFoot | theHarvester | Maltego |
|---|---|---|---|---|
| 8 fuentes OSINT concurrentes | ✅ | ✅ (módulos) | ✅ | ✅ |
| Auditoría de headers HTTP por host | ✅ | ❌ | ❌ | ❌ |
| ASM + GitHub dorks integrados | ✅ | ✅ | ❌ | ✅ |
| Correlación Shodan → CVE | ✅ | ✅ | ❌ | ✅ |
| Export de subdominios para pipelines | ✅ | ✅ | ✅ | ❌ |
| JSON / HTML CI/CD ready | ✅ | ✅ | ✅ | ❌ |
| Self-hosted, sin licencia comercial | ✅ | ✅ | ✅ | ❌ (comercial) |
| Integración directa con VSL tools | ✅ | ❌ | ❌ | ❌ |

- Combina enumeración pasiva y auditoría activa de headers en un único paso: no se necesitan herramientas adicionales para obtener la postura HTTP de los hosts descubiertos.
- El export `--subs-out` permite encadenar directamente con `vamp-subdomain-takeover` sin pasos manuales intermedios.
- La correlación Shodan → CVE añade contexto de riesgo real sobre los hosts activos, sin enviar tráfico al target durante la fase de enumeración.
- Integrado de forma nativa con `vamp-orchestrator`: los findings RECON-NNN se agregan automáticamente al informe unificado del engagement.

---

## Check Coverage

| Área | Fuentes / Checks | Fase |
|---|---|---|
| Enumeración de subdominios | crt.sh, OTX, HackerTarget, Wayback, AnubisDB, urlscan.io, RapidDNS, BufferOver | Fase 1 |
| Certificate Transparency | CT logs profundos, dominios adicionales, certificados wildcard | Fase 2 ASM |
| GitHub exposure | Dorks: `.env`, `api_key`, `password`, `secret` en repositorios públicos | Fase 2 ASM |
| Infraestructura expuesta | Banners de servicios internos, paneles de administración, staging accesible | Fase 2 ASM |
| HTTP security headers | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Permissions-Policy | Fase 3 |
| Server information leakage | Cabeceras Server / X-Powered-By con versión de software expuesta | Fase 3 |
| Cookie security flags | Ausencia de atributos Secure, HttpOnly y SameSite | Fase 3 |
| Shodan CVE correlation | Port scan, banners de servicio, CVEs por versión en hosts activos | Fase 4 (opcional) |

---

## Part of VampSecure Labs Toolkit

`vamp-passive-recon` is part of the **VampSecure Labs Security Research Toolkit** — a collection of professional-grade, self-hosted security assessment tools.

| Tool | Purpose |
|------|---------|
| [vamp-forticheck](https://github.com/belky-me/vamp-forticheck) | Multi-vendor edge device CVE scanner |
| [vamp-cve-oracle](https://github.com/belky-me/vamp-cve-oracle) | CVE intelligence and RBVM engine |
| [vamp-passive-recon](https://github.com/belky-me/vamp-passive-recon) | Passive recon and attack surface mapping |
| [vamp-subdomain-takeover](https://github.com/belky-me/vamp-subdomain-takeover) | Subdomain takeover vulnerability scanner |
| [vamp-cloud-enum](https://github.com/belky-me/vamp-cloud-enum) | Cloud storage bucket enumerator |
| [vamp-orchestrator](https://github.com/belky-me/vamp-orchestrator) | Multi-tool assessment orchestrator |

---

<p align="center">
  © VampSecure Studios — VampSecure Labs Security Research Division<br/>
  For authorized security assessments only. Unauthorized use is prohibited.
</p>

---

## Versión
v1.2.0 — VampSecure Labs Security Research Division
