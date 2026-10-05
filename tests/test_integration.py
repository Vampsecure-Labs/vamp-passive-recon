# © VampSecure Studios — VampSecure Labs Security Research Division
"""Tests de integración para vamp-passive-recon."""

import pytest
import asyncio
import json
from unittest.mock import patch, MagicMock, AsyncMock
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

pytestmark = pytest.mark.integration

# Parchear dependencias internas antes de importar el módulo
with patch.dict("sys.modules", {
    "asm": MagicMock(),
    "sources": MagicMock(),
    "headers": MagicMock(),
    "reporter": MagicMock(),
    "vampsec_report": MagicMock(),
    "rich": MagicMock(),
    "rich.console": MagicMock(),
    "rich.panel": MagicMock(),
}):
    import vamp_passive_recon as vpr


# ── Test 1: ShodanEnricher — respuesta completa mockeada ─────────────────────

@pytest.mark.asyncio
async def test_shodan_enricher_flujo_completo():
    """
    Verifica el flujo completo de ShodanEnricher.enrich() con una
    sesión aiohttp completamente mockeada.
    """
    respuesta_mock = {
        "total": 2,
        "matches": [
            {
                "ip_str": "5.6.7.8",
                "port": 443,
                "org": "Test Org",
                "country_name": "Spain",
                "hostnames": ["test.ejemplo.com"],
                "product": "nginx",
                "version": "1.25.0",
                "transport": "tcp",
                "data": "HTTP/1.1 200 OK",
                "vulns": {"CVE-2024-9999": {}},
            },
        ],
    }

    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.json = AsyncMock(return_value=respuesta_mock)

    mock_get = MagicMock()
    mock_get.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_get.__aexit__ = AsyncMock(return_value=False)

    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_get)

    mock_ctx = MagicMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
    mock_ctx.__aexit__ = AsyncMock(return_value=False)

    with patch("aiohttp.ClientSession", return_value=mock_ctx):
        enricher = vpr.ShodanEnricher("test-api-key")
        result = await enricher.enrich("ejemplo.com")

    # Verificar que el resultado tiene la estructura esperada
    assert result.domain == "ejemplo.com"
    assert result.total_hosts == 2
    assert len(result.hosts) >= 1
    assert result.hosts[0].ip == "5.6.7.8"
    assert "CVE-2024-9999" in result.all_vulns


# ── Test 2: ShodanEnricher — manejo de HTTP 401 ───────────────────────────────

@pytest.mark.asyncio
async def test_shodan_enricher_maneja_401():
    """
    Verifica que un HTTP 401 de Shodan establece el campo error y no lanza excepción.
    """
    mock_resp = AsyncMock()
    mock_resp.status = 401

    mock_get = MagicMock()
    mock_get.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_get.__aexit__ = AsyncMock(return_value=False)

    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_get)

    mock_ctx = MagicMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
    mock_ctx.__aexit__ = AsyncMock(return_value=False)

    with patch("aiohttp.ClientSession", return_value=mock_ctx):
        enricher = vpr.ShodanEnricher("clave-invalida")
        result = await enricher.enrich("ejemplo.com")

    assert result.error is not None
    assert "401" in result.error or "inválida" in result.error


# ── Test 3: CensysCollector — flujo con respuesta válida ─────────────────────

@pytest.mark.asyncio
async def test_censys_collector_flujo_completo():
    """
    Verifica el flujo de CensysCollector.collect() con respuesta mockeada.
    """
    respuesta_mock = {
        "result": {
            "total": 1,
            "hits": [
                {
                    "ip": "192.168.1.1",
                    "location": {"country": "Spain"},
                    "autonomous_system": {"asn": 11111, "description": "Test ISP"},
                    "services": [{"port": 443, "service_name": "HTTPS"}],
                },
            ],
        }
    }

    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.json = AsyncMock(return_value=respuesta_mock)

    mock_get = MagicMock()
    mock_get.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_get.__aexit__ = AsyncMock(return_value=False)

    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_get)

    mock_ctx = MagicMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
    mock_ctx.__aexit__ = AsyncMock(return_value=False)

    with patch("aiohttp.ClientSession", return_value=mock_ctx):
        collector = vpr.CensysCollector("test-id", "test-secret")
        result = await collector.collect("ejemplo.com")

    assert result.domain == "ejemplo.com"
    assert result.total_hosts == 1
    assert result.hosts[0].ip == "192.168.1.1"
    assert 443 in result.all_ports


# ── Test 4: VirusTotalCollector — flujo con respuesta válida ─────────────────

@pytest.mark.asyncio
async def test_virustotal_collector_flujo_completo():
    """
    Verifica que VirusTotalCollector.collect() parsea subdominios correctamente.
    """
    respuesta_mock = {
        "data": [
            {
                "id": "app.ejemplo.com",
                "attributes": {
                    "last_dns_records_date": "2026-10-01",
                    "last_analysis_stats": {
                        "malicious": 0, "suspicious": 0, "harmless": 50, "undetected": 2,
                    },
                },
            },
        ]
    }

    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.json = AsyncMock(return_value=respuesta_mock)

    mock_get = MagicMock()
    mock_get.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_get.__aexit__ = AsyncMock(return_value=False)

    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_get)

    mock_ctx = MagicMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
    mock_ctx.__aexit__ = AsyncMock(return_value=False)

    with patch("aiohttp.ClientSession", return_value=mock_ctx):
        collector = vpr.VirusTotalCollector("test-vt-key")
        result = await collector.collect("ejemplo.com")

    assert result.domain == "ejemplo.com"
    assert len(result.subdomains) == 1
    assert result.subdomains[0].fqdn == "app.ejemplo.com"
    assert result.subdomains[0].vt_score.startswith("0/")


# ── Test 5: LeakIXCollector — respuesta 404 (dominio sin resultados) ──────────

@pytest.mark.asyncio
async def test_leakix_collector_404_sin_error():
    """
    Un HTTP 404 de LeakIX debe devolver un resultado vacío sin error (dominio
    desconocido es normal).
    """
    mock_resp = AsyncMock()
    mock_resp.status = 404

    mock_get = MagicMock()
    mock_get.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_get.__aexit__ = AsyncMock(return_value=False)

    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_get)

    mock_ctx = MagicMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
    mock_ctx.__aexit__ = AsyncMock(return_value=False)

    with patch("aiohttp.ClientSession", return_value=mock_ctx):
        collector = vpr.LeakIXCollector("test-leakix-key")
        result = await collector.collect("ejemplo.com")

    # 404 = dominio sin resultados → no debe haber error
    assert result.error is None
    assert len(result.services) == 0
    assert result.leaks == 0
