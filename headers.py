"""
headers.py
----------
Análisis pasivo de cabeceras HTTP.

Estrategia: recoger las cabeceras de escaneos públicos ya existentes
(urlscan.io y Wayback Machine) SIN enviar tráfico al target.

Detecta:
  - Fugas de información: Server, X-Powered-By, X-AspNet-Version, X-Generator, ...
  - Cabeceras de seguridad ausentes: HSTS, CSP, X-Frame-Options, ...
  - Cookies inseguras (sin Secure / HttpOnly / SameSite)
  - CORS permisivos (Access-Control-Allow-Origin: *)
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from typing import Dict, List, Tuple
from urllib.parse import quote_plus

import aiohttp

USER_AGENT = "VampSecureLabs-PassiveRecon/2.0"
DEFAULT_TIMEOUT = aiohttp.ClientTimeout(total=30)

# ---------------------------------------------------------------------------
# Reglas de análisis
# ---------------------------------------------------------------------------

# Cabeceras que filtran información tecnológica / versiones.
LEAKY_HEADERS = {
    "server": "Revela el software del servidor y a menudo su versión.",
    "x-powered-by": "Revela el stack tecnológico (PHP, ASP.NET, Express...).",
    "x-aspnet-version": "Revela versión específica de ASP.NET.",
    "x-aspnetmvc-version": "Revela versión específica de ASP.NET MVC.",
    "x-generator": "Revela el CMS o generador (Drupal, Hugo...).",
    "x-drupal-cache": "Confirma uso de Drupal.",
    "x-varnish": "Confirma uso de Varnish como caché.",
    "x-backend-server": "Expone nombres internos de backend.",
    "x-served-by": "Expone nodos internos de CDN o backend.",
    "via": "Puede revelar proxies intermedios y sus versiones.",
    "x-runtime": "Revela tiempos internos (típico de Rails).",
    "x-cf-powered-by": "Revela uso de ColdFusion y versión.",
    "x-php-version": "Revela versión de PHP.",
    "liferay-portal": "Revela versión de Liferay.",
}

# Cabeceras de seguridad recomendadas; si faltan -> hallazgo.
SECURITY_HEADERS = {
    "strict-transport-security": "HSTS ausente: el cliente no es forzado a HTTPS.",
    "content-security-policy": "CSP ausente: sin mitigación contra XSS / inyección.",
    "x-frame-options": "X-Frame-Options ausente: riesgo de clickjacking (si no hay CSP frame-ancestors).",
    "x-content-type-options": "X-Content-Type-Options ausente: permite MIME sniffing.",
    "referrer-policy": "Referrer-Policy ausente: fuga de URLs internas al navegar fuera.",
    "permissions-policy": "Permissions-Policy ausente: sin control de APIs del navegador.",
}


@dataclass
class Finding:
    severity: str  # "info" | "low" | "medium" | "high"
    category: str
    header: str
    detail: str
    value: str | None = None


@dataclass
class HeaderReport:
    url: str
    source: str              # "urlscan.io" | "wayback"
    status: int | None
    observed_at: str | None
    headers: Dict[str, str]
    findings: List[Finding] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Análisis
# ---------------------------------------------------------------------------

_VERSION_RE = re.compile(r"\d+(?:\.\d+)+")


def analyze_headers(headers: Dict[str, str]) -> List[Finding]:
    """Aplica las reglas de análisis sobre un diccionario de cabeceras."""
    findings: List[Finding] = []
    lower = {k.lower(): v for k, v in headers.items()}

    # 1) Cabeceras con fuga de información
    for h, reason in LEAKY_HEADERS.items():
        if h in lower:
            value = lower[h]
            severity = "medium" if _VERSION_RE.search(value) else "low"
            findings.append(Finding(
                severity=severity,
                category="Information Disclosure",
                header=h,
                detail=reason,
                value=value,
            ))

    # 2) Cabeceras de seguridad ausentes
    for h, reason in SECURITY_HEADERS.items():
        if h not in lower:
            findings.append(Finding(
                severity="medium",
                category="Missing Security Header",
                header=h,
                detail=reason,
            ))

    # 3) HSTS débil
    if "strict-transport-security" in lower:
        hsts = lower["strict-transport-security"].lower()
        m = re.search(r"max-age=(\d+)", hsts)
        if m and int(m.group(1)) < 31536000:
            findings.append(Finding(
                severity="low",
                category="Weak Security Header",
                header="strict-transport-security",
                detail=f"max-age={m.group(1)} es inferior a 1 año (31536000).",
                value=hsts,
            ))

    # 4) Cookies inseguras
    set_cookie = headers.get("set-cookie") or headers.get("Set-Cookie")
    if set_cookie:
        flags = set_cookie.lower()
        missing = []
        if "secure" not in flags:
            missing.append("Secure")
        if "httponly" not in flags:
            missing.append("HttpOnly")
        if "samesite" not in flags:
            missing.append("SameSite")
        if missing:
            findings.append(Finding(
                severity="high" if "HttpOnly" in missing else "medium",
                category="Insecure Cookie",
                header="set-cookie",
                detail=f"Cookie sin flags: {', '.join(missing)}",
                value=set_cookie[:200],
            ))

    # 5) CORS permisivo
    acao = lower.get("access-control-allow-origin")
    if acao == "*":
        findings.append(Finding(
            severity="medium",
            category="CORS Misconfiguration",
            header="access-control-allow-origin",
            detail="Permite cualquier origen (*). Peligroso si hay credenciales.",
            value=acao,
        ))

    # 6) X-Frame-Options redundante o laxo
    xfo = lower.get("x-frame-options", "").upper()
    if xfo and xfo not in ("DENY", "SAMEORIGIN"):
        findings.append(Finding(
            severity="low",
            category="Weak Security Header",
            header="x-frame-options",
            detail=f"Valor no estándar: {xfo}",
            value=xfo,
        ))

    return findings


# ---------------------------------------------------------------------------
# Recolectores pasivos
# ---------------------------------------------------------------------------

class UrlScanFetcher:
    """Descarga cabeceras de escaneos previos en urlscan.io."""

    name = "urlscan.io"

    async def collect(
        self,
        session: aiohttp.ClientSession,
        host: str,
        max_scans: int = 1,
    ) -> List[HeaderReport]:
        search = f"https://urlscan.io/api/v1/search/?q=domain%3A{quote_plus(host)}&size=5"
        reports: List[HeaderReport] = []
        try:
            async with session.get(search, timeout=DEFAULT_TIMEOUT) as r:
                if r.status != 200:
                    return reports
                data = await r.json()
        except Exception:
            return reports

        results = data.get("results", [])[:max_scans]
        for res in results:
            uuid = res.get("_id")
            if not uuid:
                continue
            detail_url = f"https://urlscan.io/api/v1/result/{uuid}/"
            try:
                async with session.get(detail_url, timeout=DEFAULT_TIMEOUT) as r:
                    if r.status != 200:
                        continue
                    detail = await r.json()
            except Exception:
                continue

            # La respuesta principal suele ser la primera
            data_reqs = detail.get("data", {}).get("requests", [])
            if not data_reqs:
                continue
            primary = data_reqs[0].get("response", {}).get("response", {})
            headers = primary.get("headers") or {}
            if not headers:
                continue
            reports.append(HeaderReport(
                url=res.get("page", {}).get("url", host),
                source=self.name,
                status=primary.get("status"),
                observed_at=res.get("task", {}).get("time"),
                headers=dict(headers),
            ))
        return reports


class WaybackFetcher:
    """Obtiene cabeceras desde snapshots del Internet Archive."""

    name = "wayback"

    async def collect(
        self,
        session: aiohttp.ClientSession,
        host: str,
        max_snapshots: int = 1,
    ) -> List[HeaderReport]:
        # CDX devuelve los snapshots más recientes con código 200
        cdx = (
            "https://web.archive.org/cdx/search/cdx"
            f"?url={quote_plus(host)}&output=json&limit=-{max_snapshots}&filter=statuscode:200"
        )
        reports: List[HeaderReport] = []
        try:
            async with session.get(cdx, timeout=DEFAULT_TIMEOUT) as r:
                if r.status != 200:
                    return reports
                rows = await r.json(content_type=None)
        except Exception:
            return reports

        for row in rows[1:]:  # omitir cabecera
            timestamp, original = row[1], row[2]
            snapshot_url = f"https://web.archive.org/web/{timestamp}id_/{original}"
            try:
                async with session.head(
                    snapshot_url, allow_redirects=True, timeout=DEFAULT_TIMEOUT
                ) as r:
                    # Las cabeceras de Wayback vienen con prefijo X-Archive-Orig-
                    orig = {
                        k[len("X-Archive-Orig-"):].lower(): v
                        for k, v in r.headers.items()
                        if k.lower().startswith("x-archive-orig-")
                    }
                    if not orig:
                        continue
                    reports.append(HeaderReport(
                        url=original,
                        source=self.name,
                        status=r.status,
                        observed_at=timestamp,
                        headers=orig,
                    ))
            except Exception:
                continue
        return reports


# ---------------------------------------------------------------------------
# API pública
# ---------------------------------------------------------------------------

class HeaderAnalyzer:

    def __init__(self, use_urlscan: bool = True, use_wayback: bool = True):
        self.fetchers = []
        if use_urlscan:
            self.fetchers.append(UrlScanFetcher())
        if use_wayback:
            self.fetchers.append(WaybackFetcher())

    async def analyze_hosts(
        self,
        hosts: List[str],
        max_per_host: int = 1,
        concurrency: int = 5,
    ) -> Dict[str, List[HeaderReport]]:
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        connector = aiohttp.TCPConnector(limit=concurrency, ssl=True)
        sem = asyncio.Semaphore(concurrency)
        result: Dict[str, List[HeaderReport]] = {}

        async with aiohttp.ClientSession(headers=headers, connector=connector) as session:

            async def work(h: str):
                async with sem:
                    host_reports: List[HeaderReport] = []
                    for f in self.fetchers:
                        try:
                            host_reports.extend(await f.collect(session, h, max_per_host))
                        except Exception:
                            continue
                    # Analizar
                    for rep in host_reports:
                        rep.findings = analyze_headers(rep.headers)
                    if host_reports:
                        result[h] = host_reports

            await asyncio.gather(*(work(h) for h in hosts))

        return result
