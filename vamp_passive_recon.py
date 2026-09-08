#!/usr/bin/env python3
"""
vamp_passive_recon.py — Motor de Reconocimiento Pasivo y ASM
=============================================================
VampSecure Labs · VampSecure Studios
Para Uso Exclusivo en Pruebas de Penetración Autorizadas — v3.0

DESCRIPCIÓN GENERAL
-------------------
Motor de reconocimiento pasivo para mapeo de subdominios, análisis de
cabeceras HTTP y gestión de superficie de ataque (ASM). Todas las consultas
se realizan exclusivamente contra fuentes públicas de terceros; en ningún
caso se envía tráfico directamente al dominio objetivo.

La validación de scope (--allowed-domains) impide reconocimiento accidental
fuera del perímetro autorizado. El resultado se presenta en consola enriquecida
(Rich), informe HTML standalone dark-theme y exportación JSON completa.

ARQUITECTURA DE EJECUCIÓN (3 fases)
-------------------------------------
  Fase 1 — Enumeración de subdominios (SubdomainEnumerator — sources.py)
    Consulta simultánea a 8 fuentes públicas mediante AsyncIO + aiohttp:
    · Certificate Transparency (crt.sh) — certificados TLS emitidos
    · AlienVault OTX Passive DNS        — registros DNS históricos
    · HackerTarget hostsearch           — búsqueda de hosts por dominio
    · Internet Archive (Wayback Machine)— URLs históricas capturadas
    · AnubisDB (jldc.me)                — DNS pasivo alternativo
    · urlscan.io                        — resultados de escaneos públicos
    · RapidDNS                          — v3.0: agregador DNS adicional
    · BufferOver                        — v3.0: datos DNS masivos (FDNS/RDNS)

  Fase 2 — Análisis de cabeceras HTTP (HeaderAnalyzer — headers.py)
    Solo si no --no-headers. Petición HEAD a cada subdominio para auditar
    cabeceras de seguridad (HSTS, CSP, X-Frame-Options, etc.).

  Fase 3 — ASM (Attack Surface Management — asm.py) [v3.0]
    · Tech Fingerprinting: urlscan.io technologies + regex en cabeceras HTTP
    · GitHub Dorks: búsqueda de .env/configs/claves expuestas (GITHUB_TOKEN)
    · Cert History: análisis de historial completo crt.sh (wildcards/expirados)

DEPENDENCIAS
------------
  aiohttp  >= 3.9.0   — Cliente HTTP asíncrono con soporte SSL opcional
  rich     >= 13.7.0  — Salida de consola con formato enriquecido y tablas

VARIABLES DE ENTORNO OPCIONALES
--------------------------------
  OTX_API_KEY    — Sube límite OTX de 10 a 1000 req/min
  GITHUB_TOKEN   — Activa GitHub Dorks (sin token: desactivado)

AUTORÍA
-------
  © VampSecure Studios — VampSecure Labs Security Research Division
  Todos los derechos reservados. Uso exclusivo en entornos autorizados.
"""

from __future__ import annotations

import argparse
import asyncio
import json as _json_mod
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel

from asm import ASMAnalyzer
from sources import SubdomainEnumerator
from headers import HeaderAnalyzer
from reporter import Reporter


VERSION   = "3.0"
TOOL_NAME = "vamp-passive-recon"

console = Console()

BANNER = r"""
  ____   ____    _    __  __ ____  _____ ____ _   _ ____  _____   _        _    ____ ____
 \ \ / / _  |  / \  |  \/  |  _ \/ ____/ ___| | | |  _ \| ____| | |      / \  | __ ) ___|
  \ V / (_| | / _ \ | |\/| | |_) \___ \| |___| | | | |_) |  _|   | |     / _ \ |  _ \___ \
   | |  \__, |/ ___ \| |  | |  __/ ___) |___  | |_| |  _ <| |___  | |___ / ___ \| |_) |__) |
   |_|     /_/_/   \_|_|  |_|_|   |____/\____|\___/|_| \_|_____| |_____/_/   \_|____/____/
     by Antonio Hernandez "Belky" — VampSecure Studios · vamp-passive-recon v3.0 · Passive Recon + ASM Engine
     ────────────────────────────────────────────────────────────────────────────
     USO EXCLUSIVO EN AUDITORÍAS AUTORIZADAS · El uso no autorizado es ilegal
"""


# =============================================================================
# INTEGRACIÓN SHODAN
# =============================================================================

@dataclass
class ShodanService:
    """Servicio expuesto detectado por Shodan en un host."""
    port:      int
    transport: str = "tcp"
    product:   str = ""
    version:   str = ""
    banner:    str = ""


@dataclass
class ShodanHostResult:
    """Resultado de enriquecimiento Shodan para una IP individual."""
    ip:        str
    org:       str = ""
    country:   str = ""
    hostnames: list = field(default_factory=list)
    ports:     list = field(default_factory=list)    # List[int]
    services:  list = field(default_factory=list)    # List[ShodanService]
    vulns:     list = field(default_factory=list)    # List[str] — CVE IDs


@dataclass
class ShodanResult:
    """Resultado agregado de la fase de enriquecimiento Shodan para un dominio."""
    domain:      str
    hosts:       list = field(default_factory=list)   # List[ShodanHostResult]
    total_hosts: int  = 0
    all_ports:   list = field(default_factory=list)   # List[int] — únicos
    all_vulns:   list = field(default_factory=list)   # List[str] — CVE IDs únicos
    error:       Optional[str] = None


class ShodanEnricher:
    """
    Enriquecimiento OSINT pasivo mediante la API pública de Shodan.

    Consulta el endpoint de búsqueda de Shodan usando la query
    `hostname:<domain>` para localizar todos los hosts indexados que
    tienen el dominio en sus registros de hostname.

    Para cada host devuelve: IPs, organización, país, puertos abiertos,
    servicios con producto/versión, y CVEs conocidos reportados por Shodan.

    La clave API se puede pasar como argumento (--shodan-key) o mediante
    la variable de entorno SHODAN_API_KEY.

    Límites del API gratuito:
      · 1 búsqueda/mes en el plan Free
      · Plan Developer (49$/mes): 100 búsquedas/mes, historial
      · Para auditorías regulares se recomienda el plan Developer o superior
    """

    _SEARCH_URL = "https://api.shodan.io/shodan/host/search"
    _RESOLVE_URL = "https://api.shodan.io/dns/resolve"

    def __init__(self, api_key: str) -> None:
        self._key = api_key

    async def enrich(self, domain: str) -> ShodanResult:
        """
        Consulta Shodan y construye un ShodanResult para el dominio dado.
        Usa aiohttp internamente con timeouts conservadores.
        """
        import aiohttp as _aiohttp
        result = ShodanResult(domain=domain)

        try:
            async with _aiohttp.ClientSession(
                headers={"User-Agent": f"{TOOL_NAME}/{VERSION}"}
            ) as session:
                await self._search_hosts(domain, session, result)
        except Exception as exc:
            result.error = str(exc)[:200]

        return result

    async def _search_hosts(
        self,
        domain: str,
        session,
        result: ShodanResult,
    ) -> None:
        """Lanza la búsqueda hostname:<domain> en Shodan y parsea los matches."""
        params = {
            "query": f"hostname:{domain}",
            "key": self._key,
            "page": "1",
        }
        try:
            async with session.get(
                self._SEARCH_URL, params=params, timeout=15, ssl=True
            ) as resp:
                if resp.status == 401:
                    result.error = "Clave API Shodan inválida o sin permisos."
                    return
                if resp.status == 429:
                    result.error = "Límite de peticiones Shodan alcanzado. Espera antes de reintentar."
                    return
                if resp.status != 200:
                    result.error = f"Shodan API respondió HTTP {resp.status}."
                    return

                data = await resp.json(content_type=None)
        except Exception as exc:
            result.error = f"Error de red consultando Shodan: {str(exc)[:100]}"
            return

        matches = data.get("matches", [])
        result.total_hosts = data.get("total", len(matches))

        seen_ips: dict = {}  # ip → ShodanHostResult

        for match in matches:
            ip = match.get("ip_str", "")
            if not ip:
                continue

            if ip not in seen_ips:
                seen_ips[ip] = ShodanHostResult(
                    ip        = ip,
                    org       = match.get("org", ""),
                    country   = match.get("country_name", ""),
                    hostnames = list(match.get("hostnames", [])),
                )

            host = seen_ips[ip]

            port = match.get("port")
            if port and port not in host.ports:
                host.ports.append(port)

            svc = ShodanService(
                port      = port or 0,
                transport = match.get("transport", "tcp"),
                product   = match.get("product", ""),
                version   = match.get("version", ""),
                banner    = (match.get("data", "") or "")[:120].replace("\n", " ").strip(),
            )
            host.services.append(svc)

            # CVEs reportados por Shodan
            for cve_id in (match.get("vulns") or {}).keys():
                if cve_id not in host.vulns:
                    host.vulns.append(cve_id)

        result.hosts = list(seen_ips.values())

        # Agregar puertos y CVEs únicos globalmente
        all_ports: set = set()
        all_vulns: set = set()
        for host in result.hosts:
            all_ports.update(host.ports)
            all_vulns.update(host.vulns)
        result.all_ports = sorted(all_ports)
        result.all_vulns = sorted(all_vulns)


# =============================================================================
# INTEGRACIÓN CENSYS
# =============================================================================

@dataclass
class CensysHostResult:
    """Host indexado por Censys con sus servicios y localización."""
    ip:       str
    asn:      int  = 0
    org:      str  = ""
    country:  str  = ""
    ports:    list = field(default_factory=list)    # List[int]
    services: list = field(default_factory=list)    # List[str] — "443/HTTPS"


@dataclass
class CensysResult:
    """Resultado agregado de búsqueda Censys para un dominio."""
    domain:      str
    hosts:       list = field(default_factory=list)
    total_hosts: int  = 0
    all_ports:   list = field(default_factory=list)
    error:       Optional[str] = None


class CensysCollector:
    """
    Enriquecimiento OSINT mediante la API v2 de Censys.

    Consulta el endpoint de búsqueda de hosts con la query
    `dns.names: <domain>` para localizar hosts que tienen el dominio
    en sus certificados TLS o registros DNS indexados.

    Credenciales: censys.io → Account → API Access (ID + Secret).
    Plan Free: 250 búsquedas/mes.
    """

    _SEARCH_URL = "https://search.censys.io/api/v2/hosts/search"

    def __init__(self, api_id: str, api_secret: str) -> None:
        import base64
        creds = f"{api_id}:{api_secret}"
        self._auth = "Basic " + base64.b64encode(creds.encode()).decode()

    async def collect(self, domain: str) -> CensysResult:
        """Consulta Censys y construye un CensysResult para el dominio dado."""
        import aiohttp as _aiohttp
        result = CensysResult(domain=domain)
        try:
            headers = {
                "Authorization": self._auth,
                "User-Agent": f"{TOOL_NAME}/{VERSION}",
            }
            params = {"q": f"dns.names: {domain}", "per_page": "50"}
            async with _aiohttp.ClientSession(headers=headers) as session:
                async with session.get(
                    self._SEARCH_URL, params=params, timeout=20, ssl=True
                ) as resp:
                    if resp.status == 401:
                        result.error = "Credenciales Censys inválidas (ID/Secret)."
                        return result
                    if resp.status == 429:
                        result.error = "Límite de peticiones Censys alcanzado."
                        return result
                    if resp.status != 200:
                        result.error = f"Censys API HTTP {resp.status}."
                        return result
                    data = await resp.json(content_type=None)
        except Exception as exc:
            result.error = f"Error de red consultando Censys: {str(exc)[:100]}"
            return result

        hits      = data.get("result", {}).get("hits", [])
        result.total_hosts = data.get("result", {}).get("total", len(hits))
        all_ports: set = set()

        for hit in hits:
            ip = hit.get("ip", "")
            if not ip:
                continue
            loc      = hit.get("location", {})
            asn_data = hit.get("autonomous_system", {})
            ports: list = []
            service_labels: list = []
            for svc in hit.get("services", []):
                p = svc.get("port")
                if p:
                    ports.append(p)
                    all_ports.add(p)
                    label = f"{p}/{svc.get('service_name', '?').upper()}"
                    service_labels.append(label)
            result.hosts.append(CensysHostResult(
                ip      = ip,
                asn     = asn_data.get("asn", 0),
                org     = asn_data.get("description", ""),
                country = loc.get("country", ""),
                ports   = ports,
                services= service_labels,
            ))

        result.all_ports = sorted(all_ports)
        return result


# =============================================================================
# INTEGRACIÓN VIRUSTOTAL
# =============================================================================

@dataclass
class VTSubdomain:
    """Subdominio descubierto por VirusTotal con su puntuación de seguridad."""
    fqdn:      str
    last_seen: str = ""
    vt_score:  str = ""    # "maliciosas/total"


@dataclass
class VTResult:
    """Resultado de consulta VirusTotal para un dominio."""
    domain:     str
    subdomains: list = field(default_factory=list)
    error:      Optional[str] = None


class VirusTotalCollector:
    """
    Descubrimiento de subdominios mediante la API v3 de VirusTotal.

    Consulta el endpoint /domains/{domain}/subdomains para recuperar
    subdominios conocidos junto a su puntuación de seguridad agregada
    de los motores de análisis de VT.

    Clave API: virustotal.com → Perfil → API Key.
    Plan Free: 500 peticiones/día, 4 por minuto.
    """

    _BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str) -> None:
        self._key = api_key

    async def collect(self, domain: str) -> VTResult:
        """Recupera subdominios de VirusTotal para el dominio dado."""
        import aiohttp as _aiohttp
        result = VTResult(domain=domain)
        try:
            headers = {
                "x-apikey": self._key,
                "User-Agent": f"{TOOL_NAME}/{VERSION}",
            }
            url    = f"{self._BASE_URL}/domains/{domain}/subdomains"
            params = {"limit": "40"}
            async with _aiohttp.ClientSession(headers=headers) as session:
                async with session.get(
                    url, params=params, timeout=20, ssl=True
                ) as resp:
                    if resp.status == 401:
                        result.error = "Clave API VirusTotal inválida."
                        return result
                    if resp.status == 429:
                        result.error = "Límite de peticiones VirusTotal alcanzado."
                        return result
                    if resp.status != 200:
                        result.error = f"VirusTotal API HTTP {resp.status}."
                        return result
                    data = await resp.json(content_type=None)
        except Exception as exc:
            result.error = f"Error de red consultando VirusTotal: {str(exc)[:100]}"
            return result

        for entry in data.get("data", []):
            attrs    = entry.get("attributes", {})
            stats    = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total    = sum(stats.values())
            result.subdomains.append(VTSubdomain(
                fqdn      = entry.get("id", ""),
                last_seen = attrs.get("last_dns_records_date", ""),
                vt_score  = f"{malicious}/{total}" if total else "",
            ))

        return result


# =============================================================================
# INTEGRACIÓN LEAKIX
# =============================================================================

@dataclass
class LeakIXService:
    """Servicio o fuga indexada por LeakIX."""
    ip:       str
    port:     int
    protocol: str  = ""
    summary:  str  = ""
    is_leak:  bool = False    # True si el plugin detectó una fuga de datos


@dataclass
class LeakIXResult:
    """Resultado de búsqueda LeakIX para un dominio."""
    domain:   str
    services: list = field(default_factory=list)
    leaks:    int  = 0
    error:    Optional[str] = None


class LeakIXCollector:
    """
    Búsqueda de servicios expuestos y fugas de datos mediante la API de LeakIX.

    Consulta el endpoint /domain/<domain> para recuperar servicios indexados
    y posibles fugas de datos asociadas (bases de datos expuestas, paneles
    sin autenticación, etc.).

    Clave API: app.leakix.net → Account → API Key.
    Sin clave el endpoint devuelve solo servicios, sin datos de fugas.
    """

    _BASE_URL = "https://leakix.net"

    def __init__(self, api_key: str = "") -> None:
        self._key = api_key

    async def collect(self, domain: str) -> LeakIXResult:
        """Consulta LeakIX y construye un LeakIXResult para el dominio dado."""
        import aiohttp as _aiohttp
        result = LeakIXResult(domain=domain)
        try:
            headers: dict = {
                "Accept": "application/json",
                "User-Agent": f"{TOOL_NAME}/{VERSION}",
            }
            if self._key:
                headers["api-key"] = self._key
            url = f"{self._BASE_URL}/domain/{domain}"
            async with _aiohttp.ClientSession(headers=headers) as session:
                async with session.get(url, timeout=20, ssl=True) as resp:
                    if resp.status == 401:
                        result.error = "Clave API LeakIX inválida."
                        return result
                    if resp.status == 429:
                        result.error = "Límite de peticiones LeakIX alcanzado."
                        return result
                    if resp.status == 404:
                        return result    # dominio sin resultados — normal
                    if resp.status != 200:
                        result.error = f"LeakIX API HTTP {resp.status}."
                        return result
                    data = await resp.json(content_type=None)
        except Exception as exc:
            result.error = f"Error de red consultando LeakIX: {str(exc)[:100]}"
            return result

        if not isinstance(data, list):
            data = []

        for entry in data:
            is_leak = bool(entry.get("leak", {}).get("stage"))
            svc = LeakIXService(
                ip       = entry.get("ip", ""),
                port     = int(entry.get("port", 0) or 0),
                protocol = entry.get("protocol", ""),
                summary  = (entry.get("summary", "") or "")[:120],
                is_leak  = is_leak,
            )
            result.services.append(svc)
            if is_leak:
                result.leaks += 1

        return result


def _load_dotenv() -> None:
    """
    Carga variables de entorno desde .env en el mismo directorio.
    No sobrescribe variables ya definidas (docker run -e tiene prioridad).
    """
    env_path = Path(__file__).resolve().parent / ".env"
    if not env_path.is_file():
        return
    try:
        for raw in env_path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value
    except Exception:
        pass


_load_dotenv()


def _validate_scope(domain: str, allowed_domains: list[str]) -> bool:
    """
    Valida que el dominio objetivo está dentro del scope autorizado.

    Si --allowed-domains no se especifica, se acepta cualquier dominio.
    Si se especifica, el dominio debe ser igual o subdominio de alguno
    de los dominios autorizados.
    """
    if not allowed_domains:
        return True
    domain = domain.lower().strip()
    for allowed in allowed_domains:
        allowed = allowed.lower().strip()
        if domain == allowed or domain.endswith("." + allowed):
            return True
    return False


def parse_args() -> argparse.Namespace:
    """Parsea argumentos de línea de comandos."""
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(
            f"VampSecure Labs Passive Recon v{VERSION} — "
            "Reconocimiento pasivo + ASM (8 fuentes · tech fingerprint · GitHub dorks · cert history)"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Ejemplos:
  %(prog)s -d ejemplo.com
  %(prog)s -d ejemplo.com --no-asm --max-hosts 20
  %(prog)s -d ejemplo.com --json salida.json --html salida.html
  %(prog)s -d sub.ejemplo.com --allowed-domains ejemplo.com,otro.com
  GITHUB_TOKEN=ghp_xxx %(prog)s -d ejemplo.com   # activa GitHub dorks
        """,
    )
    p.add_argument("-d", "--domain", required=True, help="Dominio raíz objetivo")
    p.add_argument("--allowed-domains", metavar="DOM1,DOM2",
                   help="Lista de dominios autorizados separados por coma (scope)")
    p.add_argument("--no-headers", action="store_true",
                   help="Omitir fase de análisis de cabeceras HTTP")
    p.add_argument("--no-asm", action="store_true",
                   help="Omitir fase ASM (tech fingerprint, GitHub dorks, cert history)")
    p.add_argument("--max-hosts", type=int, default=15,
                   help="Máximo de hosts a analizar para cabeceras (default: 15)")
    p.add_argument("--concurrency", type=int, default=5,
                   help="Peticiones simultáneas en fase de cabeceras (default: 5)")
    p.add_argument("--json", metavar="FILE",
                   help="Escribir reporte completo en JSON")
    p.add_argument("--html", metavar="FILE",
                   help="Escribir reporte HTML")
    p.add_argument("--subs-out", metavar="FILE",
                   help="Escribir lista plana de subdominios descubiertos")
    p.add_argument("--quiet", action="store_true",
                   help="Suprimir banner y salida decorativa")
    p.add_argument("--shodan-key", metavar="API_KEY",
                   help="Clave API de Shodan (o variable SHODAN_API_KEY) para enriquecimiento "
                        "OSINT — habilita Fase 4: puertos, servicios, CVEs indexados")
    p.add_argument("--censys-id", metavar="API_ID",
                   help="ID de API Censys (o var CENSYS_API_ID) — habilita Fase 5: "
                        "hosts indexados por certificado TLS/DNS")
    p.add_argument("--censys-secret", metavar="API_SECRET",
                   help="Secret de API Censys (o var CENSYS_API_SECRET; requerido junto a --censys-id)")
    p.add_argument("--vt-key", metavar="API_KEY",
                   help="Clave API VirusTotal (o var VT_API_KEY) — habilita Fase 6: "
                        "subdominios conocidos con puntuación de seguridad")
    p.add_argument("--leakix-key", metavar="API_KEY",
                   help="Clave API LeakIX (o var LEAKIX_API_KEY) — habilita Fase 7: "
                        "servicios expuestos y fugas de datos indexadas")
    from vampsec_report import add_report_args
    add_report_args(p)
    return p.parse_args()


async def run(args: argparse.Namespace) -> int:
    """Orquesta las tres fases de reconocimiento pasivo y ASM."""
    console_local = Console()
    reporter = Reporter(console_local)

    if not args.quiet:
        console_local.print(Panel.fit(
            f"Objetivo: [bold]{args.domain}[/]\n"
            f"Modo: pasivo (sin tráfico al target) · Fuentes: 8\n"
            f"ASM: {'desactivado (--no-asm)' if args.no_asm else 'activo'} · "
            f"GitHub Dorks: {'activo (GITHUB_TOKEN)' if os.environ.get('GITHUB_TOKEN') else 'desactivado (sin GITHUB_TOKEN)'}\n"
            f"Versión: {VERSION}",
            title="[bold cyan]VampSecure Labs — Passive Recon + ASM[/]",
            border_style="cyan",
        ))

    # Validación de scope
    allowed = [d.strip() for d in args.allowed_domains.split(",")] if args.allowed_domains else []
    if not _validate_scope(args.domain, allowed):
        console_local.print(
            f"[bold red]ERROR DE SCOPE:[/] '{args.domain}' no está en la lista de dominios "
            f"autorizados: {', '.join(allowed)}\n"
            "Añade el dominio a --allowed-domains si es un objetivo autorizado."
        )
        return 1

    if allowed:
        console_local.print(f"[green]✔ Scope validado:[/] {args.domain} ∈ {{{', '.join(allowed)}}}\n")

    # ── Fase 1: Enumeración de subdominios ───────────────────────────────────
    console_local.print("\n[bold]>> Fase 1: enumeración pasiva de subdominios (8 fuentes)[/]\n")
    enumerator = SubdomainEnumerator()
    with console_local.status(
        "[cyan]Consultando fuentes: crt.sh · OTX · HackerTarget · Wayback · "
        "AnubisDB · urlscan · RapidDNS · BufferOver…[/]",
        spinner="dots",
    ):
        subs, src_results = await enumerator.enumerate(args.domain)

    reporter.print_source_summary(src_results)
    console_local.print()
    if subs:
        reporter.print_subdomains(args.domain, subs)
    else:
        console_local.print("[yellow]No se descubrieron subdominios.[/]")

    # ── Fase 2: Análisis de cabeceras HTTP ───────────────────────────────────
    header_reports = {}
    if not args.no_headers and subs:
        console_local.print("\n[bold]>> Fase 2: análisis de cabeceras HTTP[/]\n")
        hosts = sorted(subs)
        if args.domain not in hosts:
            hosts = [args.domain] + hosts
        hosts = hosts[: args.max_hosts]

        analyzer = HeaderAnalyzer()
        with console_local.status(f"[cyan]Recolectando cabeceras de {len(hosts)} hosts…[/]"):
            header_reports = await analyzer.analyze_hosts(
                hosts,
                max_per_host=1,
                concurrency=args.concurrency,
            )
        reporter.print_header_findings(header_reports)

    # ── Fase 3: ASM ──────────────────────────────────────────────────────────
    asm_result = None
    if not args.no_asm:
        console_local.print("\n[bold]>> Fase 3: ASM — Attack Surface Management[/]\n")

        # Construir dict plano {host: headers_dict} para fingerprinting de tech
        flat_headers: dict = {}
        for host, reps in header_reports.items():
            for rep in reps:
                if rep.headers:
                    flat_headers[host] = rep.headers
                    break

        github_token = os.environ.get("GITHUB_TOKEN")
        asm_analyzer = ASMAnalyzer(github_token=github_token)
        with console_local.status("[cyan]ASM: fingerprinting · cert history · GitHub dorks…[/]"):
            asm_result = await asm_analyzer.analyze(args.domain, flat_headers)

        reporter.print_asm_results(asm_result)

    # ── Fase 4: Enriquecimiento Shodan (opcional) ────────────────────────────
    shodan_result = None
    shodan_key = getattr(args, "shodan_key", None) or os.environ.get("SHODAN_API_KEY", "")
    if shodan_key:
        console_local.print("\n[bold]>> Fase 4: enriquecimiento Shodan OSINT[/]\n")
        enricher = ShodanEnricher(shodan_key)
        with console_local.status("[cyan]Consultando Shodan API…[/]", spinner="dots"):
            shodan_result = await enricher.enrich(args.domain)
        reporter.print_shodan_results(shodan_result)

    # ── Fase 5: Enriquecimiento Censys (opcional) ─────────────────────────────
    censys_result = None
    censys_id     = getattr(args, "censys_id", None) or os.environ.get("CENSYS_API_ID", "")
    censys_secret = getattr(args, "censys_secret", None) or os.environ.get("CENSYS_API_SECRET", "")
    if censys_id and censys_secret:
        console_local.print("\n[bold]>> Fase 5: enriquecimiento Censys (hosts por TLS/DNS)[/]\n")
        censys_col = CensysCollector(censys_id, censys_secret)
        with console_local.status("[cyan]Consultando Censys API…[/]", spinner="dots"):
            censys_result = await censys_col.collect(args.domain)
        if censys_result.error:
            console_local.print(f"[yellow]⚠ Censys: {censys_result.error}[/]")
        else:
            console_local.print(
                f"  Hosts indexados: [bold]{censys_result.total_hosts}[/] · "
                f"Puertos únicos: {len(censys_result.all_ports)}"
            )
            for host in censys_result.hosts[:10]:
                console_local.print(
                    f"  [cyan]{host.ip}[/] ({host.country}) — "
                    + ", ".join(host.services[:5])
                )

    # ── Fase 6: Subdominios VirusTotal (opcional) ─────────────────────────────
    vt_result = None
    vt_key = getattr(args, "vt_key", None) or os.environ.get("VT_API_KEY", "")
    if vt_key:
        console_local.print("\n[bold]>> Fase 6: subdominios VirusTotal[/]\n")
        vt_col = VirusTotalCollector(vt_key)
        with console_local.status("[cyan]Consultando VirusTotal API…[/]", spinner="dots"):
            vt_result = await vt_col.collect(args.domain)
        if vt_result.error:
            console_local.print(f"[yellow]⚠ VirusTotal: {vt_result.error}[/]")
        else:
            new_subs = {s.fqdn for s in vt_result.subdomains if s.fqdn} - subs
            subs.update(new_subs)
            console_local.print(
                f"  Subdominios VT: [bold]{len(vt_result.subdomains)}[/] · "
                f"Nuevos (no en otras fuentes): {len(new_subs)}"
            )
            flagged = [s for s in vt_result.subdomains
                       if s.vt_score and not s.vt_score.startswith("0/")]
            if flagged:
                console_local.print(
                    f"  [red]⚠ {len(flagged)} subdominios con detecciones en VirusTotal[/]"
                )

    # ── Fase 7: LeakIX — servicios expuestos y fugas (opcional) ───────────────
    leakix_result = None
    leakix_key = getattr(args, "leakix_key", None) or os.environ.get("LEAKIX_API_KEY", "")
    if leakix_key is not None and leakix_key != "":
        console_local.print("\n[bold]>> Fase 7: LeakIX — servicios expuestos y fugas[/]\n")
        leakix_col = LeakIXCollector(leakix_key)
        with console_local.status("[cyan]Consultando LeakIX…[/]", spinner="dots"):
            leakix_result = await leakix_col.collect(args.domain)
        if leakix_result.error:
            console_local.print(f"[yellow]⚠ LeakIX: {leakix_result.error}[/]")
        else:
            console_local.print(
                f"  Servicios indexados: [bold]{len(leakix_result.services)}[/] · "
                f"Fugas detectadas: [bold {'red' if leakix_result.leaks else 'green'}]"
                f"{leakix_result.leaks}[/]"
            )
            for svc in leakix_result.services[:8]:
                icon = "[red]FUGA[/]" if svc.is_leak else "svc"
                console_local.print(
                    f"  [{icon}] {svc.ip}:{svc.port}/{svc.protocol} — {svc.summary[:60]}"
                )

    # ── Salidas a fichero ─────────────────────────────────────────────────────
    if args.subs_out:
        Path(args.subs_out).write_text("\n".join(sorted(subs)) + "\n", encoding="utf-8")
        console_local.print(f"\n[green]✔[/] Subdominios guardados en {args.subs_out}")

    if args.json:
        Path(args.json).write_text(
            reporter.to_json(args.domain, subs, src_results, header_reports, asm=asm_result,
                             shodan=shodan_result),
            encoding="utf-8",
        )
        console_local.print(f"[green]✔[/] Reporte JSON en {args.json}")

    if args.html:
        Path(args.html).write_text(
            reporter.to_html(args.domain, subs, src_results, header_reports, asm=asm_result,
                             shodan=shodan_result),
            encoding="utf-8",
        )
        console_local.print(f"[green]✔[/] Reporte HTML en {args.html}")

    # Informes de cliente (formato unificado VSL)
    if args.report_html or args.report_pdf:
        from vampsec_report import VampSecReport, meta_from_args
        meta    = meta_from_args(args, tool=TOOL_NAME, version=VERSION)
        vsl_rep = VampSecReport(meta, _findings_vsl(args.domain, subs, header_reports, asm_result,
                                                     shodan=shodan_result,
                                                     vt=vt_result, leakix=leakix_result))
        if args.report_html:
            vsl_rep.to_html_client(args.report_html)
            console_local.print(f"[green]✔[/] Informe cliente HTML: {args.report_html}")
        if args.report_pdf:
            try:
                vsl_rep.to_pdf(args.report_pdf)
                console_local.print(f"[green]✔[/] Informe cliente PDF: {args.report_pdf}")
            except RuntimeError as e:
                console_local.print(f"[yellow]⚠ PDF no generado: {e}[/yellow]")

    return 0


def main() -> None:
    """Punto de entrada principal."""
    console.print(BANNER, style="bold cyan")

    args = parse_args()
    try:
        exit_code = asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\nInterrumpido por el usuario.", file=sys.stderr)
        sys.exit(130)
    sys.exit(exit_code)


# =============================================================================
# CONVERSIÓN A FORMATO DE INFORME UNIFICADO VSL
# =============================================================================

def _findings_vsl(domain: str, subs: set, header_reports: dict, asm_result,
                  shodan=None, vt=None, leakix=None) -> list:
    """
    Convierte los resultados de vamp-passive-recon al formato Finding de vampsec_report.

    Genera tres tipos de hallazgos:
      · Hallazgos de cabeceras HTTP (medium/high) por subdominio
      · Hallazgos de GitHub dorks (exposición de secretos o configuraciones)
      · Hallazgos de certs inusuales (wildcards expirados, issuers inusuales)

    Los subdominios en sí mismos son superficie de ataque (contexto) pero no
    hallazgos individuales; se reportan en el campo scope del informe.
    """
    from vampsec_report import Finding as VSLFinding

    SEV_MAP = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO"}
    INCLUDE = {"HIGH", "MEDIUM"}
    findings = []
    n = 0

    # ── Hallazgos de cabeceras HTTP ──
    for host, reports in header_reports.items():
        for rep in reports:
            for f in rep.findings:
                sev = SEV_MAP.get(f.severity.lower(), "INFO")
                if sev not in INCLUDE:
                    continue
                n += 1
                findings.append(VSLFinding(
                    id          = f"RECON-{n:03d}",
                    title       = f"{f.category}: {f.header}"[:80],
                    severity    = sev,
                    description = f.detail,
                    evidence    = (
                        f"Host: {host}\n"
                        f"Cabecera: {f.header}\n"
                        + (f"Valor: {f.value}" if f.value else "Cabecera ausente")
                    ),
                    affected    = host,
                    remediation = (
                        "Revisar la política de cabeceras de seguridad del servidor. "
                        "Implementar la cabecera con los valores recomendados según OWASP."
                    ),
                    tags        = ["http-headers", "passive-recon", f.category.lower()],
                ))

    # ── Hallazgos de GitHub dorks ──
    if asm_result and asm_result.github_findings:
        for gh in asm_result.github_findings:
            n += 1
            findings.append(VSLFinding(
                id          = f"RECON-{n:03d}",
                title       = f"Exposición en GitHub: {gh.dork}"[:80],
                severity    = "HIGH",
                description = (
                    f"Se ha encontrado contenido potencialmente sensible del dominio {domain} "
                    f"en un repositorio GitHub público mediante el dork: '{gh.dork}'."
                ),
                evidence    = (
                    f"Repositorio: {gh.repo_full_name}\n"
                    f"Fichero: {gh.file_path}\n"
                    f"URL: {gh.html_url}\n"
                    + (f"Extracto:\n{gh.excerpt[:300]}" if gh.excerpt else "")
                ),
                affected    = domain,
                remediation = (
                    "Revisar el repositorio indicado y eliminar o rotar las credenciales expuestas. "
                    "Evaluar si es necesario invalidar tokens/claves afectadas. "
                    "Añadir .gitignore y secret scanning en el repositorio origen."
                ),
                tags        = ["github-dork", "secrets", "asm"],
            ))

    # ── Hallazgos de certs inusuales ──
    if asm_result and asm_result.cert_history:
        for cert in asm_result.cert_history:
            if not (cert.is_expired or cert.is_unusual_issuer):
                continue
            n += 1
            flags = []
            if cert.is_expired:
                flags.append("Certificado EXPIRADO")
            if cert.is_unusual_issuer:
                flags.append(f"Issuer inusual: {cert.issuer}")
            if cert.is_wildcard:
                flags.append("Wildcard (*.dominio)")
            findings.append(VSLFinding(
                id          = f"RECON-{n:03d}",
                title       = f"Certificado TLS: {', '.join(flags)}"[:80],
                severity    = "MEDIUM" if cert.is_expired else "LOW",
                description = (
                    f"Se ha detectado un certificado TLS con características inusuales para {cert.cn}. "
                    f"Indicadores: {', '.join(flags)}."
                ),
                evidence    = (
                    f"CN: {cert.cn}\n"
                    f"Issuer: {cert.issuer}\n"
                    f"Válido: {cert.not_before} → {cert.not_after}\n"
                    f"SAN entries: {cert.san_count}"
                ),
                affected    = domain,
                remediation = (
                    "Renovar certificados expirados. Verificar que el issuer es una CA de confianza "
                    "y que los wildcards tienen un scope justificado."
                ),
                tags        = ["tls", "certificate", "asm"],
            ))

    # ── Hallazgos Shodan: puertos peligrosos y CVEs indexados ──
    if shodan and not shodan.error:
        PUERTOS_PELIGROSOS = {
            21: "FTP", 23: "Telnet", 111: "RPC/portmap", 137: "NetBIOS",
            139: "SMB", 445: "SMB", 512: "rexec", 513: "rlogin",
            514: "rsh/syslog", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
            5900: "VNC", 6379: "Redis", 7001: "WebLogic", 8080: "HTTP proxy",
            27017: "MongoDB", 9200: "Elasticsearch",
        }
        # Hallazgo de puertos de alto riesgo expuestos
        peligrosos = [p for p in shodan.all_ports if p in PUERTOS_PELIGROSOS]
        if peligrosos:
            n += 1
            desc_ports = ", ".join(
                f"{p} ({PUERTOS_PELIGROSOS[p]})" for p in sorted(peligrosos)
            )
            findings.append(VSLFinding(
                id          = f"RECON-{n:03d}",
                title       = f"Puertos de alto riesgo expuestos (Shodan): {len(peligrosos)} servicios",
                severity    = "HIGH",
                description = (
                    f"Shodan ha indexado los siguientes puertos de alto riesgo expuestos a Internet "
                    f"en hosts asociados a {domain}: {desc_ports}."
                ),
                evidence    = (
                    f"Puertos peligrosos: {desc_ports}\n"
                    f"Hosts afectados: {len(shodan.hosts)}\n"
                    f"Fuente: Shodan (datos históricos — verificar estado actual)"
                ),
                affected    = domain,
                remediation = (
                    "Revisar si los servicios indicados deben estar expuestos a Internet. "
                    "Aplicar reglas de firewall para restringir acceso por IP de origen. "
                    "Deshabilitar servicios no necesarios (Telnet, RDP público, etc.)."
                ),
                tags        = ["shodan", "attack-surface", "exposed-services"],
            ))

        # Hallazgos de CVEs reportados por Shodan
        for cve_id in shodan.all_vulns[:10]:  # Máximo 10 CVEs en el informe de cliente
            n += 1
            # Intentar identificar hosts con este CVE
            afectados = [h.ip for h in shodan.hosts if cve_id in h.vulns]
            findings.append(VSLFinding(
                id          = f"RECON-{n:03d}",
                title       = f"CVE Shodan: {cve_id} en hosts de {domain}",
                severity    = "HIGH",
                description = (
                    f"Shodan ha indexado el CVE {cve_id} como presente en hosts asociados a {domain}. "
                    "Verificar si el parche correspondiente ha sido aplicado."
                ),
                evidence    = (
                    f"CVE: {cve_id}\n"
                    f"IPs afectadas (Shodan): {', '.join(afectados[:5])}\n"
                    f"Fuente: Shodan — los datos de Shodan pueden tener latencia de semanas"
                ),
                affected    = domain,
                remediation = (
                    f"Verificar el estado actual de {cve_id} en los hosts indicados. "
                    "Consultar el NVD para los detalles del parche y aplicarlo si procede. "
                    f"Referencia: https://nvd.nist.gov/vuln/detail/{cve_id}"
                ),
                cve         = cve_id,
                tags        = ["shodan", "cve", "osint"],
            ))

    # ── Hallazgos LeakIX: fugas de datos ──
    if leakix and not leakix.error and leakix.leaks:
        fugas = [s for s in leakix.services if s.is_leak]
        n += 1
        evidencia = "\n".join(
            f"  {s.ip}:{s.port}/{s.protocol} — {s.summary[:80]}"
            for s in fugas[:10]
        )
        findings.append(VSLFinding(
            id          = f"RECON-{n:03d}",
            title       = f"LeakIX: {leakix.leaks} fugas de datos indexadas en {domain}",
            severity    = "CRITICAL",
            description = (
                f"LeakIX ha indexado {leakix.leaks} fuga(s) de datos activas asociadas "
                f"al dominio {domain}. Estas fugas pueden incluir bases de datos expuestas, "
                "paneles sin autenticación o ficheros de configuración accesibles públicamente."
            ),
            evidence    = f"Fugas indexadas:\n{evidencia}",
            affected    = domain,
            remediation = (
                "Identificar y cerrar inmediatamente los servicios expuestos listados. "
                "Revocar credenciales y rotar secretos que puedan haber sido accesibles. "
                "Aplicar autenticación y restricción de acceso por IP a los servicios afectados. "
                "Referencia: https://leakix.net"
            ),
            tags        = ["leakix", "data-leak", "critical-exposure"],
        ))

    # ── Hallazgos VirusTotal: subdominios marcados como maliciosos ──
    if vt and not vt.error:
        maliciosos = [s for s in vt.subdomains
                      if s.vt_score and not s.vt_score.startswith("0/")]
        for sub_vt in maliciosos[:5]:
            n += 1
            findings.append(VSLFinding(
                id          = f"RECON-{n:03d}",
                title       = f"Subdominio marcado como malicioso en VT: {sub_vt.fqdn}"[:80],
                severity    = "HIGH",
                description = (
                    f"VirusTotal reporta detecciones de seguridad para el subdominio {sub_vt.fqdn} "
                    f"({sub_vt.vt_score} motores). Puede indicar compromiso, phishing o "
                    "distribución de malware desde un subdominio del dominio auditado."
                ),
                evidence    = (
                    f"Subdominio: {sub_vt.fqdn}\n"
                    f"Detecciones VT: {sub_vt.vt_score}\n"
                    f"Última actividad: {sub_vt.last_seen or 'desconocida'}"
                ),
                affected    = sub_vt.fqdn,
                remediation = (
                    "Revisar el subdominio en VirusTotal para obtener el detalle de las detecciones. "
                    "Si el subdominio está comprometido, deshabilitar o redirigir su DNS. "
                    "Notificar a los usuarios que puedan haber interactuado con él."
                ),
                tags        = ["virustotal", "malicious-subdomain", "threat-intel"],
            ))

    return findings


if __name__ == "__main__":
    main()
