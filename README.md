<!-- © VampSecure Studios — VampSecure Labs Security Research Division -->
<p align="center">
  <img src="https://img.shields.io/badge/version-1.2.1-crimson?style=flat-square" />
  <img src="https://img.shields.io/badge/python-3.11+-blue?style=flat-square&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/async-aiohttp-teal?style=flat-square" />
  <img src="https://img.shields.io/badge/VampSecure_Labs-Security_Research-8b0000?style=flat-square" />
  <img src="https://github.com/Vampsecure-Labs/vamp-passive-recon/actions/workflows/ci.yml/badge.svg" alt="CI"/>
</p>

<h1 align="center">vamp-passive-recon</h1>
<p align="center"><em>Passive Recon &amp; Attack Surface Mapping Engine — VampSecure Labs</em></p>

> 🇬🇧 [English](#english) · 🇪🇸 [Español](#español)

---

<a name="english"></a>
## 🇬🇧 English

**vamp-passive-recon** is a modular passive reconnaissance tool that discovers subdomains, maps the external attack surface, and audits HTTP security headers — entirely through open-source intelligence sources, without sending a single packet directly to the target during enumeration.

The engine queries **eight OSINT sources** concurrently, deduplicates and validates results, and runs an Attack Surface Management (ASM) analysis phase that examines Certificate Transparency logs, GitHub dorks, and exposed infrastructure metadata. An optional Shodan enrichment phase appends service fingerprints and known CVEs to live hosts.

---

### Features

- Eight concurrent OSINT sources: crt.sh, AlienVault OTX Passive DNS, HackerTarget, Wayback Machine, AnubisDB, urlscan.io, RapidDNS, BufferOver
- ASM phase: Certificate Transparency analysis, GitHub dork enumeration (requires `GITHUB_TOKEN`), exposed infrastructure detection
- HTTP security header audit per active host: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Permissions-Policy, Server information leakage, Set-Cookie flag analysis
- Optional Shodan enrichment for service fingerprinting and CVE correlation
- Scope enforcement via `--allowed-domains` to restrict analysis to authorized targets
- Subdomain export for use as input to other VSL tools (e.g., vamp-subdomain-takeover)
- Three output formats: Rich console, JSON, HTML

---

### Requirements

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

### Installation

```bash
pip install vamp-passive-recon
# or with Homebrew:
brew install vampsecure-labs/labs/vamp-passive-recon
```

```bash
git clone https://github.com/Vampsecure-Labs/vamp-passive-recon.git
cd vamp-passive-recon
pip install -r requirements.txt
```

---

### Configuration

| Variable | Purpose | Required |
|----------|---------|----------|
| `OTX_API_KEY` | AlienVault OTX Passive DNS enrichment | Optional — increases OTX data volume |
| `GITHUB_TOKEN` | GitHub dork queries in the ASM phase | Optional — required for GitHub ASM |

```bash
export OTX_API_KEY=your_otx_key
export GITHUB_TOKEN=your_github_token
```

---

### Usage

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

### Examples

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

### Output Formats

| Format | How to enable | Description |
|--------|---------------|-------------|
| Console | Default | Rich panels: subdomain table, ASM findings, header audit summary |
| JSON | `--json FILE` | All findings with source attribution, header scores, and ASM data |
| HTML | `--html FILE` | Standalone report with tabbed sections for each analysis phase |
| Subdomains | `--subs-out FILE` | Plain text subdomain list for pipeline chaining |

---

### Exit Codes

| Code | Meaning | CI/CD usage |
|------|---------|-------------|
| `0` | Recon complete — no high-severity header or ASM findings | Pass gate |
| `1` | Moderate findings (missing security headers, minor exposure) | Review recommended |
| `2` | High-severity ASM findings or critical header misconfigurations | Fail gate |

---

### Analysis Phases

| Phase | Sources / Actions |
|-------|------------------|
| 1. Subdomain enumeration | crt.sh, OTX, HackerTarget, Wayback, AnubisDB, urlscan.io, RapidDNS, BufferOver |
| 2. ASM analysis | Certificate Transparency deep scan, GitHub dorks, exposed service detection |
| 3. Header audit | HEAD request per active host — security header presence and configuration |
| 4. Shodan enrichment | Port scan results, service banners, CVE annotations (optional) |

---

### Sample Output

```bash
$ python vamp_passive_recon.py -d example.com \
    --allowed-domains example.com,api.example.com \
    --shodan-key YOUR_KEY \
    --json recon.json --html report.html
```

```
╭──────────────────────────────────────────────────────────────────────────────╮
│  vamp-passive-recon v1.2.1 · VampSecure Labs Security Research Division      │
│  Target: example.com  ·  Shodan: enabled  ·  Concurrency: 5                 │
╰──────────────────────────────────────────────────────────────────────────────╯

Phase 1 — Subdomain enumeration
  Querying: crt.sh, OTX, HackerTarget, Wayback, AnubisDB, urlscan.io, RapidDNS, BufferOver
  ✓ 47 subdomains discovered, 38 unique after deduplication

Phase 2 — ASM (Attack Surface Mapping)
  → Certificate Transparency: 12 certificates analyzed, 3 additional domains
  → GitHub dorks: 1 relevant result — possible .env file exposed in public repo
  → Exposed infrastructure: 2 hosts with internal service banner

Phase 3 — HTTP header audit (15 active hosts)
  ✓ 15 hosts audited
  ⚠ Missing CSP:              9/15 hosts
  ⚠ Missing HSTS:             4/15 hosts
  ⚠ Missing X-Frame-Options: 11/15 hosts
  ⚠ Server header exposed:    7/15 hosts (nginx/1.18.0)

Phase 4 — Shodan enrichment
  → 8 hosts with Shodan data
  → 3 CVEs correlated on active hosts

╭──────────────────────────────── ASM Findings ──────────────────────────────╮
│ Type          │ Sev.     │ Description                                       │
│ GitHub dork   │ 🔴 HIGH  │ Public repo with possible .env file               │
│ Banner leak   │ 🟠 MED   │ 2 hosts expose internal service banner            │
│ CVE correlated│ 🟠 MED   │ CVE-2021-44228 detected on 192.168.1.10          │
│ Header audit  │ 🔵 LOW   │ Missing CSP on 9/15 hosts of example.com         │
╰─────────────────────────────────────────────────────────────────────────────╯

Subdomains exported → recon.json
HTML report         → report.html
Total: 47 subdomains · 4 findings · 3 CVEs correlated
```

---

### Why vamp-passive-recon vs. SpiderFoot · theHarvester · Maltego

| Capability | vamp-passive-recon | SpiderFoot | theHarvester | Maltego |
|---|---|---|---|---|
| 8 concurrent OSINT sources | ✅ | ✅ (modules) | ✅ | ✅ |
| HTTP header audit per host | ✅ | ❌ | ❌ | ❌ |
| Integrated ASM + GitHub dorks | ✅ | ✅ | ❌ | ✅ |
| Shodan → CVE correlation | ✅ | ✅ | ❌ | ✅ |
| Subdomain export for pipelines | ✅ | ✅ | ✅ | ❌ |
| JSON / HTML CI/CD ready | ✅ | ✅ | ✅ | ❌ |
| Self-hosted, no commercial license | ✅ | ✅ | ✅ | ❌ (commercial) |
| Direct integration with VSL tools | ✅ | ❌ | ❌ | ❌ |

- Combines passive enumeration and active header auditing in a single step: no additional tools needed to assess the HTTP security posture of discovered hosts.
- The `--subs-out` export allows direct chaining with `vamp-subdomain-takeover` without manual intermediate steps.
- Shodan → CVE correlation adds real risk context to active hosts, without sending traffic to the target during the enumeration phase.
- Natively integrated with `vamp-orchestrator`: RECON-NNN findings are automatically aggregated into the unified engagement report.

---

### Check Coverage

| Area | Sources / Checks | Phase |
|---|---|---|
| Subdomain enumeration | crt.sh, OTX, HackerTarget, Wayback, AnubisDB, urlscan.io, RapidDNS, BufferOver | Phase 1 |
| Certificate Transparency | Deep CT logs, additional domains, wildcard certificates | Phase 2 ASM |
| GitHub exposure | Dorks: `.env`, `api_key`, `password`, `secret` in public repositories | Phase 2 ASM |
| Exposed infrastructure | Internal service banners, admin panels, accessible staging | Phase 2 ASM |
| HTTP security headers | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Permissions-Policy | Phase 3 |
| Server information leakage | Server / X-Powered-By headers with exposed software version | Phase 3 |
| Cookie security flags | Missing Secure, HttpOnly and SameSite attributes | Phase 3 |
| Shodan CVE correlation | Port scan, service banners, CVEs by version on active hosts | Phase 4 (optional) |

---

### Part of VampSecure Labs Toolkit

`vamp-passive-recon` is part of the **VampSecure Labs Security Research Toolkit** — a collection of professional-grade, self-hosted security assessment tools.

| Tool | Purpose |
|------|---------|
| [vamp-forticheck](https://github.com/Vampsecure-Labs/vamp-forticheck) | Multi-vendor edge device CVE scanner |
| [vamp-cve-oracle](https://github.com/Vampsecure-Labs/vamp-cve-oracle) | CVE intelligence and RBVM engine |
| [vamp-passive-recon](https://github.com/Vampsecure-Labs/vamp-passive-recon) | Passive recon and attack surface mapping |
| [vamp-subdomain-takeover](https://github.com/Vampsecure-Labs/vamp-subdomain-takeover) | Subdomain takeover vulnerability scanner |
| [vamp-cloud-enum](https://github.com/Vampsecure-Labs/vamp-cloud-enum) | Cloud storage bucket enumerator |
| [vamp-orchestrator](https://github.com/Vampsecure-Labs/vamp-orchestrator) | Multi-tool assessment orchestrator |

---

### Version History

| Version | Main changes |
|---------|-------------|
| v1.2.1 | Bilingual README (EN/ES) |
| v1.2.0 | VampSecure Labs Security Research Division — initial public release |

---

<p align="center">
  © VampSecure Studios — VampSecure Labs Security Research Division<br/>
  For authorized security assessments only. Unauthorized use is prohibited.
</p>

---

<a name="español"></a>
## 🇪🇸 Español

**vamp-passive-recon** es una herramienta de reconocimiento pasivo modular que descubre subdominios, mapea la superficie de ataque externa y audita las cabeceras de seguridad HTTP — completamente a través de fuentes de inteligencia de código abierto, sin enviar ni un solo paquete directamente al objetivo durante la enumeración.

El motor consulta **ocho fuentes OSINT** de forma concurrente, deduplica y valida los resultados, y ejecuta una fase de análisis ASM (Attack Surface Management) que examina logs de Certificate Transparency, dorks de GitHub y metadatos de infraestructura expuesta. Una fase de enriquecimiento Shodan opcional añade huellas de servicios y CVEs conocidas a los hosts activos.

---

### Características

- Ocho fuentes OSINT concurrentes: crt.sh, AlienVault OTX Passive DNS, HackerTarget, Wayback Machine, AnubisDB, urlscan.io, RapidDNS, BufferOver
- Fase ASM: análisis de Certificate Transparency, enumeración de dorks de GitHub (requiere `GITHUB_TOKEN`), detección de infraestructura expuesta
- Auditoría de cabeceras de seguridad HTTP por host activo: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Permissions-Policy, fuga de información del servidor, análisis de flags de Set-Cookie
- Enriquecimiento Shodan opcional para fingerprinting de servicios y correlación de CVEs
- Enforcement de scope mediante `--allowed-domains` para restringir el análisis a objetivos autorizados
- Exportación de subdominios para usar como entrada en otras herramientas VSL (p.ej., vamp-subdomain-takeover)
- Tres formatos de salida: consola Rich, JSON, HTML

---

### Requisitos

```
Python 3.11+
aiohttp >= 3.9.0
rich >= 13.7.0
```

Instalar dependencias:

```bash
pip install -r requirements.txt
```

---

### Instalación

```bash
pip install vamp-passive-recon
# o con Homebrew:
brew install vampsecure-labs/labs/vamp-passive-recon
```

```bash
git clone https://github.com/Vampsecure-Labs/vamp-passive-recon.git
cd vamp-passive-recon
pip install -r requirements.txt
```

---

### Configuración

| Variable | Propósito | Requerida |
|----------|-----------|-----------|
| `OTX_API_KEY` | Enriquecimiento AlienVault OTX Passive DNS | Opcional — aumenta el volumen de datos OTX |
| `GITHUB_TOKEN` | Consultas dorks de GitHub en la fase ASM | Opcional — requerida para ASM de GitHub |

```bash
export OTX_API_KEY=tu_clave_otx
export GITHUB_TOKEN=tu_token_github
```

---

### Uso

```
python vamp_passive_recon.py -d DOMINIO [OPCIONES]

Obligatorio:
  -d, --domain DOMINIO           Dominio apex objetivo a enumerar

Scope:
      --allowed-domains DOM,...  Lista de dominios separados por coma para incluir en el análisis de headers
                                 (por defecto: solo el dominio objetivo)

Control de análisis:
      --no-headers               Omitir la fase de auditoría de cabeceras HTTP de seguridad
      --no-asm                   Omitir la fase ASM (attack surface mapping)
      --max-hosts N              Máximo de hosts a sondear en el análisis de headers (por defecto: 15)
      --concurrency N            Consultas concurrentes a fuentes OSINT (por defecto: 5)

Enriquecimiento:
      --shodan-key API_KEY       Clave API de Shodan para fingerprinting de servicios

Salida:
      --json FICHERO             Guardar hallazgos en JSON
      --html FICHERO             Generar informe HTML standalone
      --subs-out FICHERO         Guardar solo la lista de subdominios (uno por línea)
      --quiet                    Suprimir salida en consola (útil para piping)
```

---

### Ejemplos

Reconocimiento pasivo básico de un dominio objetivo:

```bash
python vamp_passive_recon.py -d example.com
```

Recon completo con fase ASM e informe HTML:

```bash
python vamp_passive_recon.py -d example.com --json recon.json --html report.html
```

Exportar lista de subdominios como entrada para el escáner de subdomain takeover:

```bash
python vamp_passive_recon.py -d example.com --subs-out subdominios.txt --no-headers --no-asm
python vamp_subdomain_takeover.py -d example.com -f subdominios.txt
```

Recon con enriquecimiento Shodan y scope restringido:

```bash
python vamp_passive_recon.py -d example.com \
  --allowed-domains example.com,api.example.com \
  --shodan-key TU_CLAVE \
  --html informe_completo.html
```

---

### Formatos de salida

| Formato | Cómo activarlo | Descripción |
|---------|----------------|-------------|
| Consola | Por defecto | Paneles Rich: tabla de subdominios, hallazgos ASM, resumen de auditoría de headers |
| JSON | `--json FICHERO` | Todos los hallazgos con atribución de fuente, scores de headers y datos ASM |
| HTML | `--html FICHERO` | Informe standalone con secciones por pestañas para cada fase de análisis |
| Subdominios | `--subs-out FICHERO` | Lista de subdominios en texto plano para encadenamiento en pipelines |

---

### Exit codes

| Código | Significado | Uso en CI/CD |
|--------|-------------|-------------|
| `0` | Recon completado — sin hallazgos de alta severidad en headers o ASM | Pasar gate |
| `1` | Hallazgos moderados (headers de seguridad ausentes, exposición menor) | Revisión recomendada |
| `2` | Hallazgos ASM de alta severidad o configuraciones críticas de headers | Fallar gate |

---

### Fases de análisis

| Fase | Fuentes / Acciones |
|------|--------------------|
| 1. Enumeración de subdominios | crt.sh, OTX, HackerTarget, Wayback, AnubisDB, urlscan.io, RapidDNS, BufferOver |
| 2. Análisis ASM | Escaneo profundo de Certificate Transparency, dorks de GitHub, detección de servicios expuestos |
| 3. Auditoría de headers | Petición HEAD por host activo — presencia y configuración de cabeceras de seguridad |
| 4. Enriquecimiento Shodan | Resultados de escaneo de puertos, banners de servicios, anotaciones de CVEs (opcional) |

---

### Why vamp-passive-recon vs. SpiderFoot · theHarvester · Maltego

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

### Check Coverage

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

### Parte del toolkit VampSecure Labs

`vamp-passive-recon` forma parte del **VampSecure Labs Security Research Toolkit** — una colección de herramientas de evaluación de seguridad de nivel profesional y self-hosted.

| Herramienta | Propósito |
|-------------|-----------|
| [vamp-forticheck](https://github.com/Vampsecure-Labs/vamp-forticheck) | Escáner CVE para dispositivos de red multi-vendor |
| [vamp-cve-oracle](https://github.com/Vampsecure-Labs/vamp-cve-oracle) | Inteligencia CVE y motor RBVM |
| [vamp-passive-recon](https://github.com/Vampsecure-Labs/vamp-passive-recon) | Reconocimiento pasivo y mapeo de superficie de ataque |
| [vamp-subdomain-takeover](https://github.com/Vampsecure-Labs/vamp-subdomain-takeover) | Escáner de vulnerabilidades de subdomain takeover |
| [vamp-cloud-enum](https://github.com/Vampsecure-Labs/vamp-cloud-enum) | Enumerador de buckets de almacenamiento en la nube |
| [vamp-orchestrator](https://github.com/Vampsecure-Labs/vamp-orchestrator) | Orquestador de evaluaciones multi-herramienta |

---

### Historial de versiones

| Versión | Cambios principales |
|---------|---------------------|
| v1.2.1 | README bilingüe (EN/ES) |
| v1.2.0 | VampSecure Labs Security Research Division — versión inicial pública |

---

<p align="center">
  © VampSecure Studios — VampSecure Labs Security Research Division<br/>
  Solo para evaluaciones de seguridad autorizadas. El uso no autorizado está prohibido.
</p>
