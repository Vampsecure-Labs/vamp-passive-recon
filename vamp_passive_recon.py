#!/usr/bin/env python3
"""
vamp_passive_recon.py — VampSecure Labs · Passive Recon v2.0
=============================================================
Motor de reconocimiento pasivo para mapeo de subdominios y análisis de
cabeceras HTTP. Todas las consultas se realizan contra fuentes públicas
de terceros; NO se envía tráfico al dominio objetivo.

Fuentes consultadas
-------------------
  · Certificate Transparency (crt.sh)
  · AlienVault OTX Passive DNS
  · HackerTarget hostsearch
  · Internet Archive (Wayback Machine)
  · AnubisDB (jldc.me)
  · urlscan.io

Cambios v2.0 respecto a v1.0
-----------------------------
  · Validación de scope: --allowed-domains permite restringir a dominios
    autorizados (evita reconocimiento accidental fuera del scope)
  · User-Agent actualizado a VampSecureLabs-PassiveRecon/2.0
  · HTML report: dark-theme cyberpunk alineado con suite VampSecure Labs
  · Autoría: VampSecure Studios (VampSecure Labs Security Research Division)
  · Docstrings completas en español

Uso
---
  python vamp_passive_recon.py -d ejemplo.com
  python vamp_passive_recon.py -d ejemplo.com --headers --max-hosts 20
  python vamp_passive_recon.py -d ejemplo.com --json out.json --html out.html
  python vamp_passive_recon.py -d sub.ejemplo.com --allowed-domains ejemplo.com

Dependencias: aiohttp, rich
Variables de entorno: OTX_API_KEY (opcional, aumenta rate limit de OTX)

© VampSecure Studios — VampSecure Labs Security Research Division
Uso exclusivo en entornos autorizados. Ver LICENSE.
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
 ██╗   ██╗ █████╗ ███╗   ███╗██████╗ ███████╗███████╗ ██████╗
 ██║   ██║██╔══██╗████╗ ████║██╔══██╗██╔════╝██╔════╝██╔════╝
 ██║   ██║███████║██╔████╔██║██████╔╝███████╗█████╗  ██║
 ╚██╗ ██╔╝██╔══██║██║╚██╔╝██║██╔═══╝ ╚════██║██╔══╝  ██║
  ╚████╔╝ ██║  ██║██║ ╚═╝ ██║██║     ███████║███████╗╚██████╗
   ╚═══╝  ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝     ╚══════╝╚══════╝ ╚═════╝
   [PASSIVE-RECON v{version}] by VampSecure Labs
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
