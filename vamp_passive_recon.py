#!/usr/bin/env python3
"""
vamp_passive_recon.py — Motor de Reconocimiento Pasivo de Subdominios
======================================================================
VampSecure Labs · VampSecure Studios
Para Uso Exclusivo en Pruebas de Penetración Autorizadas — v2.0

DESCRIPCIÓN GENERAL
-------------------
Motor de reconocimiento pasivo para mapeo de subdominios y análisis de
cabeceras HTTP de un dominio objetivo. Todas las consultas se realizan
exclusivamente contra fuentes públicas de terceros; en ningún caso se envía
tráfico directamente al dominio objetivo, lo que garantiza sigilo total
durante la fase de reconocimiento.

La validación de scope (--allowed-domains) impide reconocimiento accidental
fuera del perímetro autorizado, convirtiendo la herramienta en adecuada para
entornos donde el contrato de auditoría delimita con precisión los dominios
en scope. El resultado se presenta en consola enriquecida (Rich), informe
HTML standalone dark-theme cyberpunk y exportación JSON completa.

ARQUITECTURA DE EJECUCIÓN (2 fases)
------------------------------------
  Fase 1 — Enumeración de subdominios (SubdomainEnumerator — sources.py)
    Consulta simultánea a 6 fuentes públicas mediante AsyncIO + aiohttp:
    · Certificate Transparency (crt.sh) — certificados TLS emitidos
    · AlienVault OTX Passive DNS        — registros DNS históricos
    · HackerTarget hostsearch           — búsqueda de hosts por dominio
    · Internet Archive (Wayback Machine)— URLs históricas capturadas
    · AnubisDB (jldc.me)                — DNS pasivo alternativo
    · urlscan.io                        — resultados de escaneos públicos
    Validación de scope: cada subdominio encontrado se verifica contra
    --allowed-domains antes de incluirlo en el resultado.

  Fase 2 — Análisis de cabeceras HTTP (HeaderAnalyzer — headers.py)
    Solo si --headers. Envía una petición HEAD a cada subdominio confirmado
    y audita las cabeceras de seguridad (HSTS, CSP, X-Frame-Options,
    X-Content-Type-Options, Referrer-Policy, Permissions-Policy).

DEPENDENCIAS
------------
  aiohttp  >= 3.9.0   — Cliente HTTP asíncrono con soporte SSL opcional
  rich     >= 13.7.0  — Salida de consola con formato enriquecido y tablas

AUTORÍA
-------
  © VampSecure Studios — VampSecure Labs Security Research Division
  Todos los derechos reservados. Uso exclusivo en entornos autorizados.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel

from sources import SubdomainEnumerator
from headers import HeaderAnalyzer
from reporter import Reporter


VERSION = "2.0"
TOOL_NAME = "vamp-passive-recon"

BANNER = r"""
  ____   ____    _    __  __ ____  _____ ____ _   _ ____  _____   _        _    ____ ____
 \ \ / / _  |  / \  |  \/  |  _ \/ ____/ ___| | | |  _ \| ____| | |      / \  | __ ) ___|
  \ V / (_| | / _ \ | |\/| | |_) \___ \| |___| | | | |_) |  _|   | |     / _ \ |  _ \___ \
   | |  \__, |/ ___ \| |  | |  __/ ___) |___  | |_| |  _ <| |___  | |___ / ___ \| |_) |__) |
   |_|     /_/_/   \_|_|  |_|_|   |____/\____|\___/|_| \_|_____| |_____/_/   \_|____/____/
    by VampSecure Studios · vamp-passive-recon v2.0 · Passive Subdomain Recon & Header Auditor
    ─────────────────────────────────────────────────────────────────────────────────────────
    USO EXCLUSIVO EN AUDITORÍAS AUTORIZADAS · El uso no autorizado es ilegal
"""


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
        description=f"VampSecure Labs Passive Recon v{VERSION} — Reconocimiento pasivo de subdominios y cabeceras",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Ejemplos:
  vamp-passive-recon -d ejemplo.com
  vamp-passive-recon -d ejemplo.com --headers --max-hosts 20
  vamp-passive-recon -d ejemplo.com --json salida.json --html salida.html
  vamp-passive-recon -d sub.ejemplo.com --allowed-domains ejemplo.com,otro.com
        """,
    )
    p.add_argument("-d", "--domain", required=True, help="Dominio raíz objetivo")
    p.add_argument("--allowed-domains", metavar="DOM1,DOM2",
                   help="Lista de dominios autorizados separados por coma (scope)")
    p.add_argument("--no-headers", action="store_true",
                   help="Omitir fase de análisis de cabeceras HTTP")
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
    return p.parse_args()


async def run(args: argparse.Namespace) -> int:
    """Orquesta las fases de reconocimiento pasivo."""
    console = Console()
    reporter = Reporter(console)

    if not args.quiet:
        console.print(BANNER.format(version=VERSION), style="bold cyan")
        console.print(Panel.fit(
            f"Objetivo: [bold]{args.domain}[/]\n"
            f"Modo: pasivo (sin tráfico al target)\n"
            f"Versión: {VERSION}",
            title="[bold cyan]VampSecure Labs — Passive Recon[/]",
            border_style="cyan",
        ))

    # Validación de scope
    allowed = [d.strip() for d in args.allowed_domains.split(",")] if args.allowed_domains else []
    if not _validate_scope(args.domain, allowed):
        console.print(
            f"[bold red]ERROR DE SCOPE:[/] '{args.domain}' no está en la lista de dominios "
            f"autorizados: {', '.join(allowed)}\n"
            "Añade el dominio a --allowed-domains si es un objetivo autorizado."
        )
        return 1

    if allowed:
        console.print(f"[green]✔ Scope validado:[/] {args.domain} ∈ {{{', '.join(allowed)}}}\n")

    # Fase 1: Enumeración de subdominios
    console.print("\n[bold]>> Fase 1: enumeración pasiva de subdominios[/]\n")
    enumerator = SubdomainEnumerator()
    with console.status("[cyan]Consultando fuentes públicas (crt.sh, OTX, HackerTarget…)[/]", spinner="dots"):
        subs, src_results = await enumerator.enumerate(args.domain)

    reporter.print_source_summary(src_results)
    console.print()
    if subs:
        reporter.print_subdomains(args.domain, subs)
    else:
        console.print("[yellow]No se descubrieron subdominios.[/]")

    # Fase 2: Análisis de cabeceras HTTP
    header_reports = {}
    if not args.no_headers and subs:
        console.print("\n[bold]>> Fase 2: análisis pasivo de cabeceras HTTP[/]\n")
        hosts = sorted(subs)
        if args.domain not in hosts:
            hosts = [args.domain] + hosts
        hosts = hosts[: args.max_hosts]

        analyzer = HeaderAnalyzer()
        with console.status(f"[cyan]Recolectando cabeceras de {len(hosts)} hosts…[/]"):
            header_reports = await analyzer.analyze_hosts(
                hosts,
                max_per_host=1,
                concurrency=args.concurrency,
            )
        reporter.print_header_findings(header_reports)

    # Salidas a fichero
    if args.subs_out:
        Path(args.subs_out).write_text("\n".join(sorted(subs)) + "\n", encoding="utf-8")
        console.print(f"\n[green]✔[/] Subdominios guardados en {args.subs_out}")

    if args.json:
        Path(args.json).write_text(
            reporter.to_json(args.domain, subs, src_results, header_reports),
            encoding="utf-8",
        )
        console.print(f"[green]✔[/] Reporte JSON en {args.json}")

    if args.html:
        Path(args.html).write_text(
            reporter.to_html(args.domain, subs, src_results, header_reports),
            encoding="utf-8",
        )
        console.print(f"[green]✔[/] Reporte HTML en {args.html}")

    return 0


def main() -> None:
    """Punto de entrada principal."""
    args = parse_args()
    try:
        exit_code = asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\nInterrumpido por el usuario.", file=sys.stderr)
        sys.exit(130)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
