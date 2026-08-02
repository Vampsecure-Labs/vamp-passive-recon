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
     by VampSecure Studios · vamp-passive-recon v3.0 · Passive Recon + ASM Engine
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
                                                     shodan=shodan_result))
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

def _findings_vsl(domain: str, subs: set, header_reports: dict, asm_result, shodan=None) -> list:
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

    return findings


if __name__ == "__main__":
    main()
