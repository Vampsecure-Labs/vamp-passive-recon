# © VampSecure Studios — VampSecure Labs Security Research Division
"""Fixtures compartidas para los tests de vamp-passive-recon."""

import pytest
import sys
import os

# Añadir el directorio raíz de la herramienta al path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ── Fixtures de datos de ejemplo ─────────────────────────────────────────────

@pytest.fixture
def dominio_ejemplo():
    """Dominio de prueba estándar."""
    return "ejemplo.com"


@pytest.fixture
def respuesta_crtsh_valida():
    """Respuesta JSON simulada de crt.sh con subdominios reales."""
    return [
        {"name_value": "www.ejemplo.com"},
        {"name_value": "mail.ejemplo.com"},
        {"name_value": "api.ejemplo.com"},
        {"name_value": "*.ejemplo.com"},
        {"name_value": "admin.ejemplo.com"},
    ]


@pytest.fixture
def respuesta_shodan_valida():
    """Respuesta JSON simulada de la API de Shodan con matches reales."""
    return {
        "total": 3,
        "matches": [
            {
                "ip_str": "1.2.3.4",
                "port": 443,
                "org": "Empresa Ejemplo SL",
                "country_name": "Spain",
                "hostnames": ["www.ejemplo.com", "api.ejemplo.com"],
                "product": "nginx",
                "version": "1.24.0",
                "transport": "tcp",
                "data": "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0",
                "vulns": {"CVE-2024-1234": {}, "CVE-2023-5678": {}},
            },
            {
                "ip_str": "1.2.3.5",
                "port": 80,
                "org": "Empresa Ejemplo SL",
                "country_name": "Spain",
                "hostnames": ["mail.ejemplo.com"],
                "product": "Apache",
                "version": "2.4.51",
                "transport": "tcp",
                "data": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.51",
                "vulns": {},
            },
            {
                "ip_str": "1.2.3.4",  # IP duplicada: debe fusionarse
                "port": 22,
                "org": "Empresa Ejemplo SL",
                "country_name": "Spain",
                "hostnames": [],
                "product": "OpenSSH",
                "version": "8.9",
                "transport": "tcp",
                "data": "SSH-2.0-OpenSSH_8.9",
                "vulns": {"CVE-2024-1234": {}},
            },
        ],
    }


@pytest.fixture
def respuesta_censys_valida():
    """Respuesta JSON simulada de Censys v2 con hits."""
    return {
        "result": {
            "total": 2,
            "hits": [
                {
                    "ip": "10.0.0.1",
                    "location": {"country": "Spain"},
                    "autonomous_system": {"asn": 12345, "description": "Empresa Test"},
                    "services": [
                        {"port": 443, "service_name": "HTTPS"},
                        {"port": 80, "service_name": "HTTP"},
                    ],
                },
                {
                    "ip": "10.0.0.2",
                    "location": {"country": "Germany"},
                    "autonomous_system": {"asn": 67890, "description": "Empresa Alt"},
                    "services": [{"port": 22, "service_name": "SSH"}],
                },
            ],
        }
    }


@pytest.fixture
def respuesta_virustotal_valida():
    """Respuesta JSON simulada de VirusTotal con subdominios."""
    return {
        "data": [
            {
                "id": "sub1.ejemplo.com",
                "attributes": {
                    "last_dns_records_date": "2026-09-01",
                    "last_analysis_stats": {
                        "malicious": 2, "suspicious": 1, "harmless": 40, "undetected": 5,
                    },
                },
            },
            {
                "id": "sub2.ejemplo.com",
                "attributes": {
                    "last_dns_records_date": "2026-08-15",
                    "last_analysis_stats": {
                        "malicious": 0, "suspicious": 0, "harmless": 45, "undetected": 0,
                    },
                },
            },
        ]
    }


@pytest.fixture
def respuesta_leakix_valida():
    """Respuesta JSON simulada de LeakIX con servicios expuestos."""
    return [
        {
            "ip": "1.2.3.4",
            "port": "6379",
            "protocol": "tcp",
            "summary": "Redis sin autenticación expuesto a Internet",
            "leak": {"stage": "exfiltration"},
        },
        {
            "ip": "1.2.3.5",
            "port": "443",
            "protocol": "tcp",
            "summary": "HTTPS normal",
            "leak": {},
        },
    ]


@pytest.fixture
def subdominios_ejemplo():
    """Set de subdominios de ejemplo para pruebas de ASM/headers."""
    return {"www.ejemplo.com", "mail.ejemplo.com", "api.ejemplo.com", "admin.ejemplo.com"}


@pytest.fixture
def args_basicos(dominio_ejemplo):
    """Namespace de argparse simulado con opciones básicas."""
    import argparse
    args = argparse.Namespace(
        domain=dominio_ejemplo,
        allowed_domains=None,
        no_headers=True,
        no_asm=True,
        max_hosts=10,
        concurrency=5,
        json=None,
        html=None,
        subs_out=None,
        quiet=True,
        shodan_key=None,
        censys_id=None,
        censys_secret=None,
        vt_key=None,
        leakix_key=None,
        censys=False,
        securitytrails=False,
        cve_correlate=False,
        enumerate_people=False,
        hunter_key="",
        export_oracle=None,
        report_html=None,
        report_pdf=None,
    )
    return args
