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
import os
import sys
from pathlib import Path

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

    # ── Salidas a fichero ─────────────────────────────────────────────────────
    if args.subs_out:
        Path(args.subs_out).write_text("\n".join(sorted(subs)) + "\n", encoding="utf-8")
        console_local.print(f"\n[green]✔[/] Subdominios guardados en {args.subs_out}")

    if args.json:
        Path(args.json).write_text(
            reporter.to_json(args.domain, subs, src_results, header_reports, asm=asm_result),
            encoding="utf-8",
        )
        console_local.print(f"[green]✔[/] Reporte JSON en {args.json}")

    if args.html:
        Path(args.html).write_text(
            reporter.to_html(args.domain, subs, src_results, header_reports, asm=asm_result),
            encoding="utf-8",
        )
        console_local.print(f"[green]✔[/] Reporte HTML en {args.html}")

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


if __name__ == "__main__":
    main()
