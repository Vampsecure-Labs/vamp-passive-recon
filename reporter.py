"""
reporter.py
-----------
Formateadores de salida: consola (rich), JSON y HTML.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from asm import ASMResult, GitHubFinding
from headers import HeaderReport
from sources import SourceResult


SEVERITY_STYLE = {
    "info":   "cyan",
    "low":    "yellow",
    "medium": "orange3",
    "high":   "red",
}
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


class Reporter:

    def __init__(self, console: Console | None = None):
        self.console = console or Console()

    # ------------------------------------------------------------------
    # Consola
    # ------------------------------------------------------------------

    def print_source_summary(self, source_results: List[SourceResult]) -> None:
        table = Table(title="Fuentes pasivas consultadas", show_lines=False)
        table.add_column("Fuente")
        table.add_column("Estado")
        table.add_column("Subdominios", justify="right")
        for r in source_results:
            status = "[green]OK[/]" if r.ok else f"[red]ERROR[/] {r.error}"
            table.add_row(r.name, status, str(len(r.subdomains)))
        self.console.print(table)

    def print_subdomains(self, domain: str, subdomains: Set[str]) -> None:
        tree = Tree(f"[bold blue]{domain}[/] ({len(subdomains)} subdominios)")
        for sub in sorted(subdomains):
            tree.add(sub)
        self.console.print(tree)

    def print_header_findings(self, reports: Dict[str, List[HeaderReport]]) -> None:
        if not reports:
            self.console.print("[yellow]Sin datos públicos de cabeceras para los hosts analizados.[/]")
            return

        for host, host_reports in sorted(reports.items()):
            self.console.print()
            self.console.rule(f"[bold]{host}[/]")
            for rep in host_reports:
                meta = f"[dim]fuente:[/] {rep.source}  [dim]status:[/] {rep.status}  [dim]obs:[/] {rep.observed_at}"
                self.console.print(Panel(meta, title=rep.url, expand=False))

                if not rep.findings:
                    self.console.print("[green]Sin hallazgos en esta muestra.[/]")
                    continue

                t = Table(show_lines=False)
                t.add_column("Sev.")
                t.add_column("Categoría")
                t.add_column("Cabecera")
                t.add_column("Detalle")
                t.add_column("Valor")
                sorted_findings = sorted(rep.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
                for f in sorted_findings:
                    style = SEVERITY_STYLE.get(f.severity, "white")
                    t.add_row(
                        f"[{style}]{f.severity.upper()}[/]",
                        f.category,
                        f.header,
                        f.detail,
                        (f.value or "")[:60],
                    )
                self.console.print(t)

    # ------------------------------------------------------------------
    # ASM — consola
    # ------------------------------------------------------------------

    def print_asm_results(self, asm: ASMResult) -> None:
        """Muestra resultados del módulo ASM en consola con formato Rich."""
        from rich.rule import Rule
        from rich.panel import Panel as RichPanel

        self.console.print(Rule("[bold red]ASM — Análisis de Superficie de Ataque[/]"))

        # Tech stack
        if asm.tech_stack:
            t = Table(title="Stack tecnológico detectado (pasivo)", show_lines=False)
            t.add_column("Tecnología",  style="cyan")
            t.add_column("Versión",     width=12)
            t.add_column("Confianza",   width=10)
            t.add_column("Fuente",      width=30, style="dim")
            for tech in asm.tech_stack:
                conf_style = {"HIGH": "bold green", "MEDIUM": "yellow", "LOW": "dim"}.get(
                    tech.confidence, "white"
                )
                t.add_row(
                    tech.name,
                    tech.version or "—",
                    f"[{conf_style}]{tech.confidence}[/]",
                    tech.source,
                )
            self.console.print(t)
        else:
            self.console.print("[dim]Tech fingerprinting: sin resultados.[/]")

        # Cert history
        self.console.print()
        if asm.cert_history:
            t = Table(title=f"Historial de certificados TLS ({len(asm.cert_history)} entradas)", show_lines=False)
            t.add_column("CN",             style="cyan", width=30)
            t.add_column("Emisor",         width=30)
            t.add_column("Válido desde",   width=12)
            t.add_column("Hasta",          width=12)
            t.add_column("Flags",          width=20)
            for cert in asm.cert_history[:15]:
                flags = []
                if cert.is_wildcard:
                    flags.append("[yellow]wildcard[/]")
                if cert.is_expired:
                    flags.append("[red]expirado[/]")
                if cert.is_unusual_issuer:
                    flags.append("[bold red]emisor raro[/]")
                if cert.san_count > 10:
                    flags.append(f"[dim]{cert.san_count} SANs[/]")
                flags_str = " ".join(flags) or "[green]OK[/]"
                t.add_row(
                    cert.cn[:28], cert.issuer[:28],
                    cert.not_before, cert.not_after, flags_str,
                )
            self.console.print(t)

            wildcards    = sum(1 for c in asm.cert_history if c.is_wildcard)
            expired      = sum(1 for c in asm.cert_history if c.is_expired)
            unusual      = sum(1 for c in asm.cert_history if c.is_unusual_issuer)
            if wildcards or expired or unusual:
                self.console.print(
                    f"  [yellow]Resumen:[/] {wildcards} wildcards · "
                    f"{expired} expirados · {unusual} emisores inusuales"
                )
        else:
            self.console.print("[dim]Historial de certificados: sin datos.[/]")

        # GitHub findings
        self.console.print()
        if not asm.github_enabled:
            self.console.print(
                "[dim]GitHub dorks: desactivado (sin GITHUB_TOKEN). "
                "Exporta GITHUB_TOKEN para activar.[/]"
            )
        elif asm.github_findings:
            self.console.print(
                f"[bold red]⚠ GitHub: {len(asm.github_findings)} posibles exposiciones[/]"
            )
            for f in asm.github_findings:
                self.console.print(
                    f"  · [cyan]{f.repo_full_name}[/] — {f.file_path}\n"
                    f"    Dork: [dim]{f.dork}[/]\n"
                    f"    URL: {f.html_url}"
                )
                if f.excerpt:
                    self.console.print(
                        f"    Fragmento: [dim]{f.excerpt[:100]}…[/]"
                    )
        else:
            self.console.print("[green]GitHub dorks: sin exposiciones detectadas.[/]")

        # Errores ASM
        if asm.errors:
            for err in asm.errors:
                self.console.print(f"[yellow]  ASM warning: {err}[/]")

    # ------------------------------------------------------------------
    # JSON
    # ------------------------------------------------------------------

    def to_json(
        self,
        domain: str,
        subdomains: Set[str],
        source_results: List[SourceResult],
        header_reports: Dict[str, List[HeaderReport]],
        asm: Optional["ASMResult"] = None,
    ) -> str:
        payload = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "target": domain,
            "subdomains": sorted(subdomains),
            "sources": [
                {"name": r.name, "count": len(r.subdomains), "error": r.error}
                for r in source_results
            ],
            "headers": {
                host: [
                    {
                        "url": rep.url,
                        "source": rep.source,
                        "status": rep.status,
                        "observed_at": rep.observed_at,
                        "headers": rep.headers,
                        "findings": [asdict(f) for f in rep.findings],
                    }
                    for rep in reps
                ]
                for host, reps in header_reports.items()
            },
        }
        if asm:
            payload["asm"] = {
                "tech_stack": [asdict(t) for t in asm.tech_stack],
                "cert_history": [asdict(c) for c in asm.cert_history],
                "github_findings": [asdict(g) for g in asm.github_findings],
                "github_enabled": asm.github_enabled,
                "errors": asm.errors,
            }
        return json.dumps(payload, indent=2, ensure_ascii=False)

    # ------------------------------------------------------------------
    # HTML
    # ------------------------------------------------------------------

    def to_html(
        self,
        domain: str,
        subdomains: Set[str],
        source_results: List[SourceResult],
        header_reports: Dict[str, List[HeaderReport]],
        asm: Optional["ASMResult"] = None,
    ) -> str:
        severity_color = {
            "info":   "#4A90E2",
            "low":    "#D4A017",
            "medium": "#E67E22",
            "high":   "#C0392B",
        }

        ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

        def esc(s: str) -> str:
            return (str(s).replace("&", "&amp;").replace("<", "&lt;")
                    .replace(">", "&gt;").replace('"', "&quot;"))

        src_rows = "".join(
            f"<tr><td>{esc(r.name)}</td>"
            f"<td>{'OK' if r.ok else 'ERROR: ' + esc(r.error or '')}</td>"
            f"<td style='text-align:right'>{len(r.subdomains)}</td></tr>"
            for r in source_results
        )

        sub_list = "".join(f"<li>{esc(s)}</li>" for s in sorted(subdomains))

        header_sections = []
        for host, reps in sorted(header_reports.items()):
            blocks = []
            for rep in reps:
                if rep.findings:
                    find_rows = "".join(
                        f"<tr>"
                        f"<td style='color:{severity_color.get(f.severity, '#333')};font-weight:bold'>{f.severity.upper()}</td>"
                        f"<td>{esc(f.category)}</td>"
                        f"<td><code>{esc(f.header)}</code></td>"
                        f"<td>{esc(f.detail)}</td>"
                        f"<td><code>{esc((f.value or '')[:80])}</code></td>"
                        f"</tr>"
                        for f in sorted(rep.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
                    )
                    findings_html = (
                        "<table><thead><tr><th>Sev</th><th>Categoría</th>"
                        "<th>Cabecera</th><th>Detalle</th><th>Valor</th></tr></thead>"
                        f"<tbody>{find_rows}</tbody></table>"
                    )
                else:
                    findings_html = "<p class='ok'>Sin hallazgos en esta muestra.</p>"

                hdr_rows = "".join(
                    f"<tr><td><code>{esc(k)}</code></td><td><code>{esc(v)}</code></td></tr>"
                    for k, v in rep.headers.items()
                )

                blocks.append(
                    f"<div class='snapshot'>"
                    f"<h4>{esc(rep.url)}</h4>"
                    f"<p class='meta'>Fuente: <b>{esc(rep.source)}</b> · "
                    f"Status: {rep.status} · Observado: {esc(rep.observed_at or 'n/a')}</p>"
                    f"{findings_html}"
                    f"<details><summary>Cabeceras en bruto ({len(rep.headers)})</summary>"
                    f"<table class='raw'><tbody>{hdr_rows}</tbody></table></details>"
                    f"</div>"
                )

            header_sections.append(
                f"<section><h3>{esc(host)}</h3>{''.join(blocks)}</section>"
            )

        headers_html = "".join(header_sections) or "<p>Sin datos públicos de cabeceras.</p>"

        # Sección ASM
        asm_html = ""
        if asm:
            # Tech stack
            if asm.tech_stack:
                tech_rows = "".join(
                    f"<tr><td>{esc(t.name)}</td><td>{esc(t.version or '—')}</td>"
                    f"<td>{esc(t.confidence)}</td><td>{esc(t.source)}</td></tr>"
                    for t in asm.tech_stack
                )
                tech_section = (
                    "<h2>ASM — Stack tecnológico</h2>"
                    "<table><thead><tr><th>Tecnología</th><th>Versión</th>"
                    "<th>Confianza</th><th>Fuente</th></tr></thead>"
                    f"<tbody>{tech_rows}</tbody></table>"
                )
            else:
                tech_section = "<h2>ASM — Stack tecnológico</h2><p>Sin datos.</p>"

            # Cert history
            if asm.cert_history:
                cert_rows = ""
                for cert in asm.cert_history[:20]:
                    flags = []
                    if cert.is_wildcard:     flags.append("<span class='flag-warn'>wildcard</span>")
                    if cert.is_expired:      flags.append("<span class='flag-err'>expirado</span>")
                    if cert.is_unusual_issuer: flags.append("<span class='flag-err'>emisor raro</span>")
                    flags_html = " ".join(flags) or "<span style='color:#4caf50'>OK</span>"
                    cert_rows += (
                        f"<tr><td><code>{esc(cert.cn)}</code></td>"
                        f"<td>{esc(cert.issuer[:40])}</td>"
                        f"<td>{esc(cert.not_before)}</td>"
                        f"<td>{esc(cert.not_after)}</td>"
                        f"<td>{cert.san_count}</td>"
                        f"<td>{flags_html}</td></tr>"
                    )
                cert_section = (
                    f"<h2>ASM — Historial de certificados ({len(asm.cert_history)} entradas)</h2>"
                    "<table><thead><tr><th>CN</th><th>Emisor</th>"
                    "<th>Desde</th><th>Hasta</th><th>SANs</th><th>Flags</th></tr></thead>"
                    f"<tbody>{cert_rows}</tbody></table>"
                )
            else:
                cert_section = "<h2>ASM — Historial de certificados</h2><p>Sin datos.</p>"

            # GitHub findings
            if not asm.github_enabled:
                gh_section = (
                    "<h2>ASM — GitHub Dorks</h2>"
                    "<p class='meta'>Desactivado: exporta GITHUB_TOKEN para activar.</p>"
                )
            elif asm.github_findings:
                gh_items = "".join(
                    f"<div class='gh-finding'>"
                    f"<p><b>{esc(f.repo_full_name)}</b> — <code>{esc(f.file_path)}</code></p>"
                    f"<p class='meta'>Dork: {esc(f.dork)}</p>"
                    f"<p><a href='{esc(f.html_url)}' target='_blank'>{esc(f.html_url)}</a></p>"
                    + (f"<pre class='excerpt'>{esc(f.excerpt[:200])}</pre>" if f.excerpt else "")
                    + "</div>"
                    for f in asm.github_findings
                )
                gh_section = (
                    f"<h2 style='color:#ff4444'>⚠ ASM — GitHub: "
                    f"{len(asm.github_findings)} posibles exposiciones</h2>"
                    f"{gh_items}"
                )
            else:
                gh_section = (
                    "<h2>ASM — GitHub Dorks</h2>"
                    "<p class='ok'>Sin exposiciones detectadas.</p>"
                )

            asm_html = (
                f"<div class='asm-section'>"
                f"{tech_section}"
                f"{cert_section}"
                f"{gh_section}"
                f"</div>"
            )

        return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>VampSecure Labs — Passive Recon · {esc(domain)}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
        background:#0a0a0a;color:#e0e0e0;padding:2rem;}}
  header{{border-bottom:2px solid #00bcd4;padding-bottom:1.5rem;margin-bottom:2rem;}}
  .brand{{font-size:1.4rem;font-weight:700;color:#00bcd4;letter-spacing:.05em;}}
  .meta-bar{{color:#888;font-size:.85rem;margin-top:.5rem;}}
  h2{{color:#00bcd4;border-bottom:1px solid #1a3a3a;padding-bottom:.4rem;
      margin:1.5rem 0 .75rem;font-size:1.1rem;text-transform:uppercase;
      letter-spacing:.08em;}}
  h3{{color:#fff;background:#0d2020;padding:.5rem .8rem;border-radius:4px;
      margin:.75rem 0 .5rem;border-left:3px solid #00bcd4;}}
  table{{width:100%;border-collapse:collapse;background:#111;margin:.5rem 0;
         border:1px solid #1e1e1e;border-radius:6px;overflow:hidden;}}
  th,td{{padding:.5rem .75rem;border-bottom:1px solid #1a1a1a;text-align:left;
          vertical-align:top;font-size:.88rem;}}
  th{{background:#0d2020;color:#00bcd4;font-weight:600;font-size:.8rem;
      text-transform:uppercase;letter-spacing:.06em;}}
  code{{background:#0d0d0d;padding:.15rem .4rem;border-radius:3px;
        color:#9ecbff;font-size:.82rem;word-break:break-all;}}
  .meta{{color:#888;font-size:.82rem;}}
  .ok{{color:#4caf50;}}
  .snapshot{{background:#0d0d0d;padding:1rem;border-radius:6px;
             margin-bottom:1rem;border:1px solid #1a1a1a;}}
  details summary{{cursor:pointer;color:#00bcd4;margin-top:.5rem;font-size:.85rem;}}
  .raw td{{font-family:ui-monospace,monospace;font-size:.76rem;word-break:break-all;}}
  ul.subs{{columns:3;font-family:ui-monospace,monospace;font-size:.82rem;
            list-style:none;padding:0;}}
  ul.subs li{{padding:.2rem 0;color:#ccc;}}
  footer{{margin-top:3rem;color:#444;font-size:.8rem;text-align:center;}}
  .sev-high{{color:#ff4444;font-weight:700;}}
  .sev-medium{{color:#f0c040;font-weight:700;}}
  .sev-low{{color:#4caf50;}}
  .sev-info{{color:#4a90e2;}}
  .asm-section{{margin-top:2rem;border-top:2px solid #b00020;padding-top:1rem;}}
  .gh-finding{{background:#0d0d0d;padding:.75rem 1rem;margin:.5rem 0;
               border-left:3px solid #ff4444;border-radius:4px;}}
  .gh-finding a{{color:#9ecbff;font-size:.85rem;}}
  .excerpt{{background:#111;padding:.5rem;border-radius:4px;color:#ccc;
            font-size:.8rem;overflow-x:auto;margin-top:.4rem;}}
  .flag-warn{{background:#3a2a00;color:#f0c040;padding:.1rem .4rem;border-radius:3px;font-size:.78rem;}}
  .flag-err{{background:#2a0000;color:#ff4444;padding:.1rem .4rem;border-radius:3px;font-size:.78rem;}}
</style>
</head>
<body>
  <header>
    <div class="brand">VampSecure Labs — Passive Recon v3.0 ASM</div>
    <p class="meta-bar">Target: <b>{esc(domain)}</b> · Generado: {ts} · Modo: pasivo (sin tráfico al objetivo)</p>
  </header>

  <h2>Fuentes consultadas</h2>
  <table><thead><tr><th>Fuente</th><th>Estado</th><th>Subdominios</th></tr></thead>
    <tbody>{src_rows}</tbody></table>

  <h2>Subdominios descubiertos ({len(subdomains)})</h2>
  <ul class="subs">{sub_list}</ul>

  <h2>Análisis de cabeceras</h2>
  {headers_html}

  {asm_html}

  <footer>
    VampSecure Labs by VampSecure Studios · Uso exclusivo en entornos autorizados ·
    Datos: crt.sh · AlienVault OTX · HackerTarget · Wayback Machine · AnubisDB · urlscan.io · RapidDNS · BufferOver
  </footer>
</body>
</html>
"""
