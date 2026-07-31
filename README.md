# vamp-passive-recon

**VampSecure Labs — Security Research Division**  
Reconocimiento pasivo de dominios: enumeración de subdominios y análisis de cabeceras HTTP.

---

## Descripción

Herramienta de OSINT/recon pasivo que realiza enumeración de subdominios e inspección de
cabeceras HTTP de seguridad sin interactuar directamente con el objetivo. Toda la información
se obtiene de fuentes públicas (Certificate Transparency, OTX, servicios de internet history)
lo que la hace apta para la fase de reconocimiento pre-autorización.

Utiliza AsyncIO para consultar hasta 6 fuentes en paralelo, con validación de scope por
dominio para asegurar que el análisis se limita a los objetivos autorizados.

## Fuentes de inteligencia

| Fuente | Tipo | Datos |
|--------|------|-------|
| crt.sh | Certificate Transparency | Subdominios por certificados TLS |
| AlienVault OTX | Threat Intel | Subdominios registrados en pulsos |
| HackerTarget | DNS Lookup | Resolución DNS masiva |
| Wayback Machine | Internet Archive | URLs históricas del dominio |
| AnubisDB | OSINT | Base de datos de subdominios |
| urlscan.io | Web Scan History | Dominios analizados públicamente |

## Análisis de cabeceras HTTP

Evalúa la presencia y configuración de cabeceras de seguridad:
- **Críticas:** CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Permissions-Policy
- **Filtración de información:** Server, X-Powered-By, X-Generator, X-AspNet-Version
- **Cookies:** flags Secure y HttpOnly en Set-Cookie

## Requisitos

- Python 3.9+
- Dependencias: `aiohttp>=3.9.0`, `rich>=13.7.0`

## Instalación

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Uso

```bash
# Recon básico de un dominio
python3 vamp_passive_recon.py ejemplo.com

# Con scope explícito (solo analiza subdominios del dominio autorizado)
python3 vamp_passive_recon.py ejemplo.com --allowed-domains ejemplo.com,subdominio.ejemplo.com

# Exportar resultados
python3 vamp_passive_recon.py ejemplo.com --output-json resultado.json --output-html resultado.html
```

## Opciones

| Opción | Descripción |
|--------|-------------|
| `domain` | Dominio objetivo |
| `--allowed-domains` | Lista de dominios autorizados separados por coma |
| `--output-json` | Guardar subdominios encontrados en JSON |
| `--output-html` | Guardar informe completo en HTML con tema oscuro |
| `--timeout` | Timeout por fuente en segundos (por defecto: 15) |
| `--concurrency` | Peticiones concurrentes por fuente (por defecto: 5) |

## Flujo de análisis

1. **Validación de scope** — Comprueba que el dominio objetivo está en la lista autorizada
2. **Enumeración de subdominios** — Consulta todas las fuentes en paralelo y deduplica
3. **Análisis de cabeceras** — Hace HEAD a cada subdominio activo y evalúa seguridad
4. **Generación de informes** — Consola Rich + ficheros JSON/HTML opcionales

## Aviso legal

Esta herramienta solo usa fuentes públicas pasivas. No realiza peticiones directas al
objetivo durante la enumeración de subdominios. El análisis de cabeceras HTTP implica
una petición HEAD por dominio activo: asegúrate de tener autorización antes de usar esta
opción en producción.

---

© VampSecure Studios — VampSecure Labs Security Research Division  
Licencia: MIT
