"""
asm.py — Módulo ASM (Attack Surface Management)
================================================
VampSecure Labs · VampSecure Studios
Para Uso Exclusivo en Pruebas de Penetración Autorizadas — v3.0

DESCRIPCIÓN
-----------
Módulo de análisis avanzado de superficie de ataque complementario al
reconocimiento pasivo de subdominios. Proporciona tres capacidades diferenciadas:

  1. Tech Fingerprinting pasivo: detecta tecnologías del stack sin enviar
     tráfico al objetivo. Fuentes: urlscan.io (campo technologies de resultados
     públicos previos) + análisis regex de cabeceras HTTP ya capturadas.

  2. Búsqueda de secretos en GitHub (GitHub Dorks): consulta la Search API
     pública de GitHub para detectar credenciales, .env files u otro material
     sensible mencionando el dominio objetivo en repositorios públicos.
     Requiere GITHUB_TOKEN para evitar rate limiting severo (10 req/min sin key).
     Los patrones cubren: .env files, config.php/wp-config, claves privadas,
     contraseñas en YAML/JSON, cadenas de conexión a BD.

  3. Análisis de historial de certificados (crt.sh): consulta el historial
     completo de certificados TLS emitidos para el dominio. Detecta:
     wildcards, certificados expirados, emisores inusuales (no Let's Encrypt
     ni DigiCert), SANs que revelan dominios internos o infraestructura oculta,
     y patrones temporales de emisión de certs.

FUENTES DE DATOS
----------------
  · urlscan.io API v1     — tech stack desde escaneos públicos previos
  · crt.sh JSON API       — historial completo de certificados TLS
  · GitHub Search API v3  — dorks para secretos en repos públicos
  · cabeceras HTTP        — regex fingerprinting (headers.py captura los datos)

AUTORÍA
-------
  © VampSecure Studios — VampSecure Labs Security Research Division
  Todos los derechos reservados. Uso exclusivo en entornos autorizados.
"""

from __future__ import annotations

import asyncio
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set
from urllib.parse import quote_plus

import aiohttp

from sources import DEFAULT_TIMEOUT, USER_AGENT


# ────────────────────────────────────────────────────────────────────────────
# Constantes
# ────────────────────────────────────────────────────────────────────────────

GITHUB_SEARCH_API = "https://api.github.com/search/code"
URLSCAN_SEARCH    = "https://urlscan.io/api/v1/search/"
CRTSH_API         = "https://crt.sh/"

# Patrones de búsqueda de secretos en GitHub (se formatea con {domain})
_GITHUB_DORKS: List[str] = [
    '"{domain}" filename:.env',
    '"{domain}" filename:config.php password',
    '"{domain}" filename:wp-config.php',
    '"{domain}" extension:env DB_PASSWORD',
    '"{domain}" extension:yml password',
    '"{domain}" "PRIVATE KEY"',
    '"{domain}" api_key OR secret_key filename:*.json',
    '"{domain}" extension:sql',
]

# Patrones regex para detección de tecnologías en cabeceras HTTP
# Formato: { nombre_cabecera: [(regex, nombre_tech, confianza), ...] }
_HEADER_TECH_PATTERNS: Dict[str, List[tuple]] = {
    "Server": [
        (re.compile(r"Apache(?:[/\s](\S+))?", re.I),       "Apache HTTP",         "HIGH"),
        (re.compile(r"nginx(?:[/\s](\S+))?", re.I),         "nginx",               "HIGH"),
        (re.compile(r"Microsoft-IIS(?:[/\s](\S+))?", re.I), "Microsoft IIS",       "HIGH"),
        (re.compile(r"LiteSpeed(?:[/\s](\S+))?", re.I),     "LiteSpeed",           "MEDIUM"),
        (re.compile(r"cloudflare", re.I),                    "Cloudflare",          "HIGH"),
        (re.compile(r"openresty", re.I),                     "OpenResty",           "MEDIUM"),
        (re.compile(r"Caddy(?:[/\s](\S+))?", re.I),         "Caddy",               "HIGH"),
        (re.compile(r"Kestrel", re.I),                       "ASP.NET Core/Kestrel","MEDIUM"),
    ],
    "X-Powered-By": [
        (re.compile(r"PHP(?:[/\s](\S+))?", re.I),           "PHP",                 "HIGH"),
        (re.compile(r"ASP\.NET(?:[/\s](\S+))?", re.I),      "ASP.NET",             "HIGH"),
        (re.compile(r"Express", re.I),                       "Express.js",          "MEDIUM"),
        (re.compile(r"Next\.js", re.I),                      "Next.js",             "HIGH"),
        (re.compile(r"Phusion Passenger(?:[/\s](\S+))?", re.I), "Phusion Passenger","MEDIUM"),
    ],
    "X-Generator": [
        (re.compile(r"WordPress(?:\s+(\S+))?", re.I),        "WordPress",           "HIGH"),
        (re.compile(r"Drupal(?:\s+(\S+))?", re.I),           "Drupal",              "HIGH"),
        (re.compile(r"Joomla(?:\s+(\S+))?", re.I),           "Joomla",              "HIGH"),
        (re.compile(r"Wix", re.I),                           "Wix",                 "HIGH"),
        (re.compile(r"Ghost(?:\s+(\S+))?", re.I),            "Ghost CMS",           "HIGH"),
    ],
    "Via": [
        (re.compile(r"Varnish", re.I),                       "Varnish Cache",       "HIGH"),
        (re.compile(r"squid", re.I),                         "Squid Proxy",         "MEDIUM"),
    ],
    "X-Drupal-Cache":     [(re.compile(r".", re.I),          "Drupal",              "HIGH")],
    "X-Shopify-Stage":    [(re.compile(r".", re.I),          "Shopify",             "HIGH")],
    "X-Wix-Request-Id":   [(re.compile(r".", re.I),          "Wix",                 "HIGH")],
    "X-WordPress-Cache":  [(re.compile(r".", re.I),          "WordPress",           "HIGH")],
    "X-Joomla-CMS":       [(re.compile(r".", re.I),          "Joomla",              "HIGH")],
    "CF-Cache-Status":    [(re.compile(r".", re.I),          "Cloudflare",          "HIGH")],
    "X-Amz-Cf-Id":        [(re.compile(r".", re.I),          "AWS CloudFront",      "HIGH")],
    "X-Amzn-Trace-Id":    [(re.compile(r".", re.I),          "AWS",                 "MEDIUM")],
    "X-Vercel-Id":        [(re.compile(r".", re.I),          "Vercel",              "HIGH")],
    "X-Netlify-Id":       [(re.compile(r".", re.I),          "Netlify",             "HIGH")],
    "X-Fastly-Request-ID":[(re.compile(r".", re.I),          "Fastly CDN",          "HIGH")],
}

# Emisores de certificados que se consideran "estándar" (no merecen alertar)
_COMMON_ISSUERS_RE = re.compile(
    r"Let's Encrypt|DigiCert|GlobalSign|Comodo|Sectigo|GeoTrust"
    r"|GoDaddy|Amazon|Google Trust Services|ZeroSSL|Entrust|Symantec",
    re.I,
)


# ────────────────────────────────────────────────────────────────────────────
# Modelos de datos
# ────────────────────────────────────────────────────────────────────────────

@dataclass
class GitHubFinding:
    """Hallazgo de posible exposición de material sensible en GitHub público."""
    dork: str
    repo_full_name: str
    file_path: str
    html_url: str
    excerpt: str = ""


@dataclass
class CertHistoryEntry:
    """Entrada del historial de certificados TLS emitidos (crt.sh)."""
    cn: str
    issuer: str
    not_before: str
    not_after: str
    san_count: int = 0
    is_expired: bool = False
    is_wildcard: bool = False
    is_unusual_issuer: bool = False


@dataclass
class TechEntry:
    """Tecnología detectada de forma pasiva en el stack del objetivo."""
    name: str
    version: str = ""
    source: str = ""
    confidence: str = "LOW"   # LOW | MEDIUM | HIGH


@dataclass
class ASMResult:
    """Resultado consolidado del análisis ASM."""
    domain: str
    tech_stack: List[TechEntry] = field(default_factory=list)
    cert_history: List[CertHistoryEntry] = field(default_factory=list)
    github_findings: List[GitHubFinding] = field(default_factory=list)
    github_enabled: bool = False
    errors: List[str] = field(default_factory=list)


# ────────────────────────────────────────────────────────────────────────────
# Analizador ASM
# ────────────────────────────────────────────────────────────────────────────

class ASMAnalyzer:
    """
    Orquesta las tres fases de análisis ASM:
      · Fingerprinting tecnológico (urlscan + cabeceras)
      · Búsqueda de secretos en GitHub
      · Análisis de historial de certificados (crt.sh)
    """

    def __init__(self, github_token: Optional[str] = None):
        self._github_token = github_token or os.environ.get("GITHUB_TOKEN")

    async def analyze(
        self,
        domain: str,
        header_data: Dict[str, dict],
    ) -> ASMResult:
        """
        Ejecuta el análisis ASM completo.

        :param domain: dominio objetivo
        :param header_data: dict {host: {header: valor}} con cabeceras ya capturadas
        :return: ASMResult con tech_stack, cert_history y github_findings
        """
        result = ASMResult(domain=domain, github_enabled=bool(self._github_token))
        headers_session = {
            "User-Agent": USER_AGENT,
            "Accept": "application/json, text/plain, */*",
        }
        connector = aiohttp.TCPConnector(limit=5, ssl=True)

        async with aiohttp.ClientSession(headers=headers_session, connector=connector) as session:
            tasks = [
                self._fingerprint_urlscan(session, domain),
                self._analyze_cert_history(session, domain),
            ]
            if self._github_token:
                tasks.append(self._github_dorks(session, domain))

            gathered = await asyncio.gather(*tasks, return_exceptions=True)

        # Procesar tech desde urlscan
        urlscan_tech_or_err = gathered[0]
        if isinstance(urlscan_tech_or_err, Exception):
            result.errors.append(f"urlscan tech: {urlscan_tech_or_err}")
        else:
            result.tech_stack.extend(urlscan_tech_or_err)

        # Tech desde cabeceras ya capturadas (síncrono, rápido)
        header_tech = self._fingerprint_headers(header_data)
        for tech in header_tech:
            if not any(t.name == tech.name for t in result.tech_stack):
                result.tech_stack.append(tech)

        # Cert history
        cert_or_err = gathered[1]
        if isinstance(cert_or_err, Exception):
            result.errors.append(f"cert history: {cert_or_err}")
        else:
            result.cert_history = cert_or_err

        # GitHub findings (si token disponible)
        if self._github_token and len(gathered) > 2:
            gh_or_err = gathered[2]
            if isinstance(gh_or_err, Exception):
                result.errors.append(f"GitHub dorks: {gh_or_err}")
            else:
                result.github_findings = gh_or_err

        # Ordenar tech por confianza descendente
        confidence_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        result.tech_stack.sort(key=lambda t: confidence_order.get(t.confidence, 9))

        return result

    # ── Fingerprinting tecnológico desde urlscan ─────────────────────────────

    async def _fingerprint_urlscan(
        self,
        session: aiohttp.ClientSession,
        domain: str,
    ) -> List[TechEntry]:
        """
        Consulta urlscan.io para extraer el stack tecnológico detectado en
        escaneos públicos previos del dominio. El campo 'technologies' de
        urlscan incluye nombre, versión y categoría de cada tecnología.
        """
        url = f"{URLSCAN_SEARCH}?q=domain%3A{quote_plus(domain)}&size=5"
        tech_seen: Dict[str, TechEntry] = {}

        try:
            async with session.get(url, timeout=DEFAULT_TIMEOUT) as r:
                if r.status != 200:
                    return []
                data = await r.json()
                for result in data.get("results", []):
                    for tech in result.get("technologies", []):
                        name = tech.get("name", "").strip()
                        if not name or name in tech_seen:
                            continue
                        version = tech.get("version", "")
                        tech_seen[name] = TechEntry(
                            name=name,
                            version=version,
                            source="urlscan.io",
                            confidence="MEDIUM",
                        )
        except Exception:
            pass

        return list(tech_seen.values())

    # ── Fingerprinting desde cabeceras HTTP ──────────────────────────────────

    def _fingerprint_headers(
        self,
        header_data: Dict[str, dict],
    ) -> List[TechEntry]:
        """
        Analiza las cabeceras HTTP ya capturadas para detectar tecnologías
        mediante patrones regex definidos en _HEADER_TECH_PATTERNS.
        """
        tech_seen: Dict[str, TechEntry] = {}

        for _host, headers in header_data.items():
            for header_name, patterns in _HEADER_TECH_PATTERNS.items():
                # Búsqueda case-insensitive de la cabecera
                header_val = ""
                for k, v in headers.items():
                    if k.lower() == header_name.lower():
                        header_val = str(v)
                        break
                if not header_val:
                    continue

                for regex, tech_name, confidence in patterns:
                    m = regex.search(header_val)
                    if m:
                        version = m.group(1) if m.lastindex and m.lastindex >= 1 else ""
                        if tech_name not in tech_seen:
                            tech_seen[tech_name] = TechEntry(
                                name=tech_name,
                                version=version,
                                source=f"Header: {header_name}",
                                confidence=confidence,
                            )

        return list(tech_seen.values())

    # ── Análisis de historial de certificados ────────────────────────────────

    async def _analyze_cert_history(
        self,
        session: aiohttp.ClientSession,
        domain: str,
    ) -> List[CertHistoryEntry]:
        """
        Consulta crt.sh para obtener el historial completo de certificados TLS
        emitidos para el dominio. Analiza:
        - Wildcards (*.domain.com)
        - Certificados expirados
        - Emisores inusuales (no proveedores principales)
        - Conteo de SANs (Subject Alternative Names)
        Devuelve los 30 certificados más recientes.
        """
        url = f"{CRTSH_API}?q=%25.{quote_plus(domain)}&output=json"
        entries: List[CertHistoryEntry] = []
        seen_ids: Set[str] = set()
        now = datetime.utcnow()

        try:
            async with session.get(url, timeout=DEFAULT_TIMEOUT) as r:
                if r.status != 200:
                    return []
                text = await r.text()
                import json
                try:
                    data = json.loads(text)
                except Exception:
                    data = [json.loads(line) for line in text.splitlines() if line.strip()]
        except Exception:
            return []

        # Agrupar por issuer+cn para deduplicar reediciones
        for entry in data[:200]:
            cert_id = str(entry.get("id", ""))
            if cert_id in seen_ids:
                continue
            seen_ids.add(cert_id)

            cn          = (entry.get("common_name") or "").strip()
            issuer      = (entry.get("issuer_name") or "").strip()
            not_before  = (entry.get("not_before") or "")[:10]
            not_after   = (entry.get("not_after") or "")[:10]
            san_names   = (entry.get("name_value") or "").splitlines()
            san_count   = len([s for s in san_names if s.strip()])
            is_wildcard = cn.startswith("*.")
            is_expired  = False

            try:
                exp_date = datetime.strptime(not_after, "%Y-%m-%d")
                is_expired = exp_date < now
            except ValueError:
                pass

            is_unusual_issuer = bool(issuer) and not _COMMON_ISSUERS_RE.search(issuer)

            entries.append(CertHistoryEntry(
                cn=cn,
                issuer=issuer,
                not_before=not_before,
                not_after=not_after,
                san_count=san_count,
                is_expired=is_expired,
                is_wildcard=is_wildcard,
                is_unusual_issuer=is_unusual_issuer,
            ))

        # Ordenar: más recientes primero, limitar a 30
        entries.sort(key=lambda e: e.not_before, reverse=True)
        return entries[:30]

    # ── GitHub Dorks ─────────────────────────────────────────────────────────

    async def _github_dorks(
        self,
        session: aiohttp.ClientSession,
        domain: str,
    ) -> List[GitHubFinding]:
        """
        Busca posible exposición de material sensible en repositorios GitHub
        públicos mediante patrones de búsqueda (dorks) predefinidos.

        Requiere GITHUB_TOKEN (variable de entorno) para evitar rate limiting.
        Cada patrón busca max 3 resultados para minimizar peticiones.
        Hay una pausa de 2s entre dorks para respetar rate limits de GitHub.
        """
        if not self._github_token:
            return []

        findings: List[GitHubFinding] = []
        auth_headers = {
            "Authorization": f"Bearer {self._github_token}",
            "Accept": "application/vnd.github.v3.text-match+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        for dork_tpl in _GITHUB_DORKS:
            query = dork_tpl.format(domain=domain)
            url = f"{GITHUB_SEARCH_API}?q={quote_plus(query)}&per_page=3"

            try:
                async with session.get(url, headers=auth_headers, timeout=DEFAULT_TIMEOUT) as r:
                    if r.status == 403:
                        # Rate limit o token sin permisos de búsqueda
                        break
                    if r.status != 200:
                        continue
                    data = await r.json()
            except Exception:
                continue

            for item in data.get("items", []):
                repo = item.get("repository", {}).get("full_name", "")
                path = item.get("path", "")
                html_url = item.get("html_url", "")

                # Extraer fragmento del primer text_match disponible
                excerpt = ""
                for tm in item.get("text_matches", [])[:1]:
                    excerpt = tm.get("fragment", "")[:200]

                findings.append(GitHubFinding(
                    dork=query,
                    repo_full_name=repo,
                    file_path=path,
                    html_url=html_url,
                    excerpt=excerpt,
                ))

            # Pausa para respetar rate limit de GitHub Search API
            await asyncio.sleep(2.0)

        return findings
