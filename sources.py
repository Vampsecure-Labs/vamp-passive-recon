"""
sources.py
----------
Fuentes pasivas para enumeración de subdominios.

Todas las fuentes consultan terceros (Certificate Transparency, DNS pasivo,
archivos web) y NUNCA envían tráfico directamente al dominio objetivo.
"""

from __future__ import annotations

import asyncio
import json
import os
import random
import re
from dataclasses import dataclass, field
from typing import Iterable, Set
from urllib.parse import quote_plus

import aiohttp

USER_AGENT = "VampSecureLabs-PassiveRecon/3.0 (+https://vampsecurestudios.com)"
DEFAULT_TIMEOUT = aiohttp.ClientTimeout(total=30)

# Códigos que merece la pena reintentar (rate limit o fallos transitorios)
_RETRYABLE_STATUS = {429, 500, 502, 503, 504}


async def _get_with_retries(
    session: aiohttp.ClientSession,
    url: str,
    *,
    headers: dict | None = None,
    max_attempts: int = 4,
    base_delay: float = 2.0,
) -> aiohttp.ClientResponse | None:
    """
    GET con reintentos y backoff exponencial para códigos transitorios.

    Respeta la cabecera `Retry-After` si el servidor la envía.
    Devuelve la última respuesta (incluso si es error) o None si todos los
    intentos fallaron por excepción.
    """
    last_response: aiohttp.ClientResponse | None = None
    for attempt in range(max_attempts):
        try:
            resp = await session.get(url, headers=headers, timeout=DEFAULT_TIMEOUT)
        except Exception:
            if attempt == max_attempts - 1:
                raise
            await asyncio.sleep(base_delay * (2 ** attempt) + random.uniform(0, 0.5))
            continue

        last_response = resp
        if resp.status not in _RETRYABLE_STATUS or attempt == max_attempts - 1:
            return resp

        # Backoff; honra Retry-After si viene
        retry_after = resp.headers.get("Retry-After")
        if retry_after and retry_after.isdigit():
            delay = min(int(retry_after), 30)
        else:
            delay = base_delay * (2 ** attempt) + random.uniform(0, 0.5)
        resp.release()
        await asyncio.sleep(delay)

    return last_response

# Regex amplio para validar subdominios (evita inyección de basura)
_SUBDOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+$")


def _clean(host: str, apex: str) -> str | None:
    """Normaliza un hostname y verifica que pertenece al apex indicado."""
    if not host:
        return None
    host = host.strip().lower().rstrip(".")
    # Quitar wildcards y protocolos
    host = host.removeprefix("*.").removeprefix("http://").removeprefix("https://")
    host = host.split("/", 1)[0].split(":", 1)[0]
    if not host or not _SUBDOMAIN_RE.match(host):
        return None
    if not (host == apex or host.endswith("." + apex)):
        return None
    return host


@dataclass
class SourceResult:
    """Resultado devuelto por una fuente individual."""
    name: str
    subdomains: Set[str] = field(default_factory=set)
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


class PassiveSource:
    """Clase base para una fuente pasiva."""

    name: str = "base"

    async def fetch(self, session: aiohttp.ClientSession, domain: str) -> SourceResult:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Fuentes
# ---------------------------------------------------------------------------

class CrtSh(PassiveSource):
    """Certificate Transparency vía crt.sh. Sin API key, puede ser lenta."""
    name = "crt.sh"

    async def fetch(self, session: aiohttp.ClientSession, domain: str) -> SourceResult:
        result = SourceResult(self.name)
        url = f"https://crt.sh/?q=%25.{quote_plus(domain)}&output=json"
        try:
            async with session.get(url, timeout=DEFAULT_TIMEOUT) as r:
                if r.status != 200:
                    result.error = f"HTTP {r.status}"
                    return result
                text = await r.text()
                # A veces crt.sh devuelve NDJSON concatenado
                try:
                    data = json.loads(text)
                except json.JSONDecodeError:
                    data = [json.loads(l) for l in text.splitlines() if l.strip()]
                for entry in data:
                    names = entry.get("name_value", "")
                    for name in names.splitlines():
                        cleaned = _clean(name, domain)
                        if cleaned:
                            result.subdomains.add(cleaned)
        except Exception as e:
            result.error = f"{type(e).__name__}: {e}"
        return result


class HackerTarget(PassiveSource):
    """HackerTarget hostsearch (API pública, limitada)."""
    name = "HackerTarget"

    async def fetch(self, session: aiohttp.ClientSession, domain: str) -> SourceResult:
        result = SourceResult(self.name)
        url = f"https://api.hackertarget.com/hostsearch/?q={quote_plus(domain)}"
        try:
            async with session.get(url, timeout=DEFAULT_TIMEOUT) as r:
                body = await r.text()
                if "error" in body.lower() or "api count exceeded" in body.lower():
                    result.error = body.strip()[:120]
                    return result
                for line in body.splitlines():
                    host = line.split(",", 1)[0]
                    cleaned = _clean(host, domain)
                    if cleaned:
                        result.subdomains.add(cleaned)
        except Exception as e:
            result.error = f"{type(e).__name__}: {e}"
        return result


class AlienVaultOTX(PassiveSource):
    """
    AlienVault OTX Passive DNS.

    Acepta API key opcional vía variable de entorno OTX_API_KEY, lo que
    eleva sustancialmente el rate limit. Registrarse es gratuito en
    https://otx.alienvault.com/api
    """
    name = "AlienVault OTX"

    async def fetch(self, session: aiohttp.ClientSession, domain: str) -> SourceResult:
        result = SourceResult(self.name)
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{quote_plus(domain)}/passive_dns"

        api_key = os.environ.get("OTX_API_KEY")
        extra_headers = {"X-OTX-API-KEY": api_key} if api_key else None

        try:
            r = await _get_with_retries(session, url, headers=extra_headers)
            if r is None:
                result.error = "sin respuesta"
                return result
            async with r:
                if r.status != 200:
                    if r.status == 429:
                        hint = " (añade OTX_API_KEY para evitar rate limit)" if not api_key else ""
                        result.error = f"HTTP 429 rate limit{hint}"
                    else:
                        result.error = f"HTTP {r.status}"
                    return result
                data = await r.json()
                for entry in data.get("passive_dns", []):
                    cleaned = _clean(entry.get("hostname", ""), domain)
                    if cleaned:
                        result.subdomains.add(cleaned)
        except Exception as e:
            result.error = f"{type(e).__name__}: {e}"
        return result


class WaybackMachine(PassiveSource):
    """Internet Archive CDX: extrae hostnames de URLs archivadas."""
    name = "Wayback Machine"

    async def fetch(self, session: aiohttp.ClientSession, domain: str) -> SourceResult:
        result = SourceResult(self.name)
        url = (
            "https://web.archive.org/cdx/search/cdx"
            f"?url=*.{quote_plus(domain)}/*&output=json&fl=original&collapse=urlkey"
        )
        try:
            async with session.get(url, timeout=DEFAULT_TIMEOUT) as r:
                if r.status != 200:
                    result.error = f"HTTP {r.status}"
                    return result
                data = await r.json(content_type=None)
                # La primera fila es cabecera
                for row in data[1:]:
                    if not row:
                        continue
                    original = row[0]
                    host = original.split("//", 1)[-1].split("/", 1)[0]
                    cleaned = _clean(host, domain)
                    if cleaned:
                        result.subdomains.add(cleaned)
        except Exception as e:
            result.error = f"{type(e).__name__}: {e}"
        return result


class AnubisDB(PassiveSource):
    """AnubisDB (jldc.me) - agregador de varias fuentes."""
    name = "AnubisDB"

    async def fetch(self, session: aiohttp.ClientSession, domain: str) -> SourceResult:
        result = SourceResult(self.name)
        url = f"https://jldc.me/anubis/subdomains/{quote_plus(domain)}"
        try:
            async with session.get(url, timeout=DEFAULT_TIMEOUT) as r:
                if r.status != 200:
                    result.error = f"HTTP {r.status}"
                    return result
                data = await r.json(content_type=None)
                for host in data or []:
                    cleaned = _clean(host, domain)
                    if cleaned:
                        result.subdomains.add(cleaned)
        except Exception as e:
            result.error = f"{type(e).__name__}: {e}"
        return result


class UrlScan(PassiveSource):
    """urlscan.io - busca escaneos públicos previos del dominio."""
    name = "urlscan.io"

    async def fetch(self, session: aiohttp.ClientSession, domain: str) -> SourceResult:
        result = SourceResult(self.name)
        url = f"https://urlscan.io/api/v1/search/?q=domain%3A{quote_plus(domain)}&size=1000"
        try:
            async with session.get(url, timeout=DEFAULT_TIMEOUT) as r:
                if r.status != 200:
                    result.error = f"HTTP {r.status}"
                    return result
                data = await r.json()
                for item in data.get("results", []):
                    page = item.get("page", {})
                    for key in ("domain", "apexDomain"):
                        cleaned = _clean(page.get(key, ""), domain)
                        if cleaned:
                            result.subdomains.add(cleaned)
        except Exception as e:
            result.error = f"{type(e).__name__}: {e}"
        return result


class RapidDNS(PassiveSource):
    """
    RapidDNS — agregador de DNS pasivo con cobertura amplia.
    No requiere API key. Velocidad moderada.
    """
    name = "RapidDNS"

    async def fetch(self, session: aiohttp.ClientSession, domain: str) -> SourceResult:
        result = SourceResult(self.name)
        url = f"https://rapiddns.io/subdomain/{quote_plus(domain)}?full=1&down=1"
        try:
            async with session.get(url, timeout=DEFAULT_TIMEOUT) as r:
                if r.status != 200:
                    result.error = f"HTTP {r.status}"
                    return result
                body = await r.text()
                # RapidDNS devuelve líneas "subdominio\tIP" en modo down=1
                for line in body.splitlines():
                    host = line.split("\t", 1)[0].strip()
                    cleaned = _clean(host, domain)
                    if cleaned:
                        result.subdomains.add(cleaned)
        except Exception as e:
            result.error = f"{type(e).__name__}: {e}"
        return result


class BufferOver(PassiveSource):
    """
    BufferOver DNS — fuente pasiva adicional basada en datos de resolución DNS masiva.
    API pública, sin autenticación.
    """
    name = "BufferOver"

    async def fetch(self, session: aiohttp.ClientSession, domain: str) -> SourceResult:
        result = SourceResult(self.name)
        url = f"https://dns.bufferover.run/dns?q=.{quote_plus(domain)}"
        try:
            async with session.get(url, timeout=DEFAULT_TIMEOUT) as r:
                if r.status != 200:
                    result.error = f"HTTP {r.status}"
                    return result
                data = await r.json(content_type=None)
                # Combina FDNS_A y RDNS (ambos con formato "IP,hostname")
                for entry_list_key in ("FDNS_A", "RDNS"):
                    for entry in data.get(entry_list_key) or []:
                        parts = str(entry).split(",", 1)
                        if len(parts) == 2:
                            host = parts[1].strip().rstrip(".")
                            cleaned = _clean(host, domain)
                            if cleaned:
                                result.subdomains.add(cleaned)
        except Exception as e:
            result.error = f"{type(e).__name__}: {e}"
        return result


# ---------------------------------------------------------------------------
# Orquestador
# ---------------------------------------------------------------------------

DEFAULT_SOURCES: list[type[PassiveSource]] = [
    CrtSh,
    HackerTarget,
    AlienVaultOTX,
    WaybackMachine,
    AnubisDB,
    UrlScan,
    RapidDNS,
    BufferOver,
]


class SubdomainEnumerator:
    """Lanza todas las fuentes en paralelo y consolida resultados."""

    def __init__(self, sources: Iterable[type[PassiveSource]] | None = None):
        self.sources = [s() for s in (sources or DEFAULT_SOURCES)]

    async def enumerate(self, domain: str) -> tuple[Set[str], list[SourceResult]]:
        domain = domain.lower().strip().rstrip(".")
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json, text/plain, */*"}
        connector = aiohttp.TCPConnector(limit=10, ssl=True)
        async with aiohttp.ClientSession(headers=headers, connector=connector) as session:
            tasks = [s.fetch(session, domain) for s in self.sources]
            results = await asyncio.gather(*tasks, return_exceptions=False)

        all_subs: Set[str] = set()
        for r in results:
            all_subs.update(r.subdomains)
        return all_subs, results
