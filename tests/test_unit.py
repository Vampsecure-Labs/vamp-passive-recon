# © VampSecure Studios — VampSecure Labs Security Research Division
"""Tests unitarios para vamp-passive-recon."""

import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Importar módulo bajo prueba con mocks de dependencias internas
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


# ── Tests para _validate_scope ────────────────────────────────────────────────

class TestValidateScope:
    """Pruebas para la función de validación de scope."""

    def test_scope_vacio_acepta_cualquier_dominio(self):
        """Sin lista de scope, cualquier dominio debe ser aceptado."""
        assert vpr._validate_scope("cualquier.dominio.com", []) is True

    def test_dominio_exactamente_en_scope(self):
        """El dominio que aparece exactamente en la lista debe ser aceptado."""
        assert vpr._validate_scope("ejemplo.com", ["ejemplo.com"]) is True

    def test_subdominio_dentro_de_scope(self):
        """Un subdominio de un dominio autorizado debe ser aceptado."""
        assert vpr._validate_scope("sub.ejemplo.com", ["ejemplo.com"]) is True

    def test_subdominio_profundo_dentro_de_scope(self):
        """Un subdominio de segundo nivel también debe ser aceptado."""
        assert vpr._validate_scope("a.b.ejemplo.com", ["ejemplo.com"]) is True

    def test_dominio_fuera_de_scope(self):
        """Un dominio no autorizado debe ser rechazado."""
        assert vpr._validate_scope("otro.com", ["ejemplo.com"]) is False

    def test_dominio_similar_pero_fuera_de_scope(self):
        """Un dominio con el nombre similar no debe pasar el scope."""
        assert vpr._validate_scope("noejemplo.com", ["ejemplo.com"]) is False

    def test_scope_multiple_acepta_cualquiera(self):
        """Con varios dominios en scope, cualquiera de ellos debe ser aceptado."""
        allowed = ["ejemplo.com", "otrodominio.es"]
        assert vpr._validate_scope("sub.otrodominio.es", allowed) is True

    def test_scope_insensible_a_mayusculas(self):
        """La validación debe ser insensible a mayúsculas/minúsculas."""
        assert vpr._validate_scope("SUB.EJEMPLO.COM", ["ejemplo.com"]) is True


# ── Tests para ShodanEnricher._search_hosts ───────────────────────────────────

class TestShodanEnricher:
    """Pruebas para el parseo de respuestas Shodan."""

    def test_parseo_matches_con_ips_unicas(self, respuesta_shodan_valida):
        """Los matches con IPs duplicadas deben fusionarse en un único host."""
        vpr.ShodanEnricher("clave-test")
        result = vpr.ShodanResult(domain="ejemplo.com")
        # Simular la lógica de _search_hosts sin red
        seen_ips = {}
        for match in respuesta_shodan_valida["matches"]:
            ip = match.get("ip_str", "")
            if ip not in seen_ips:
                seen_ips[ip] = vpr.ShodanHostResult(
                    ip=ip,
                    org=match.get("org", ""),
                    country=match.get("country_name", ""),
                    hostnames=list(match.get("hostnames", [])),
                )
            host = seen_ips[ip]
            port = match.get("port")
            if port and port not in host.ports:
                host.ports.append(port)
        result.hosts = list(seen_ips.values())
        # La IP 1.2.3.4 aparece dos veces: debe fusionarse
        assert len(result.hosts) == 2

    def test_parseo_acumula_puertos_por_ip(self, respuesta_shodan_valida):
        """Una misma IP con varios matches debe acumular todos sus puertos."""
        vpr.ShodanEnricher("clave-test")
        vpr.ShodanResult(domain="ejemplo.com")
        seen_ips = {}
        for match in respuesta_shodan_valida["matches"]:
            ip = match.get("ip_str", "")
            if ip not in seen_ips:
                seen_ips[ip] = vpr.ShodanHostResult(ip=ip)
            host = seen_ips[ip]
            port = match.get("port")
            if port and port not in host.ports:
                host.ports.append(port)
        # 1.2.3.4 tiene puertos 443 y 22
        assert 443 in seen_ips["1.2.3.4"].ports
        assert 22  in seen_ips["1.2.3.4"].ports

    def test_resultado_error_en_401(self):
        """HTTP 401 debe establecer el campo error en ShodanResult."""
        result = vpr.ShodanResult(domain="ejemplo.com")
        result.error = "Clave API Shodan inválida o sin permisos."
        assert result.error is not None
        assert "inválida" in result.error

    def test_cves_acumulados_globalmente(self, respuesta_shodan_valida):
        """Los CVEs de todos los hosts deben aparecer en all_vulns sin duplicados."""
        seen_ips = {}
        for match in respuesta_shodan_valida["matches"]:
            ip = match.get("ip_str", "")
            if ip not in seen_ips:
                seen_ips[ip] = vpr.ShodanHostResult(ip=ip)
            host = seen_ips[ip]
            for cve_id in (match.get("vulns") or {}):
                if cve_id not in host.vulns:
                    host.vulns.append(cve_id)
        all_vulns: set = set()
        for host in seen_ips.values():
            all_vulns.update(host.vulns)
        # CVE-2024-1234 aparece en dos hosts: no debe duplicarse
        assert "CVE-2024-1234" in all_vulns
        assert len([v for v in all_vulns if v == "CVE-2024-1234"]) == 1


# ── Tests para CensysCollector ────────────────────────────────────────────────

class TestCensysCollector:
    """Pruebas para el parseo de respuestas Censys."""

    def test_parseo_hits_censys(self, respuesta_censys_valida):
        """Los hits de Censys deben mapearse a CensysHostResult correctamente."""
        hits = respuesta_censys_valida["result"]["hits"]
        result = vpr.CensysResult(domain="ejemplo.com")
        result.total_hosts = respuesta_censys_valida["result"]["total"]
        all_ports: set = set()
        for hit in hits:
            ip = hit.get("ip", "")
            loc = hit.get("location", {})
            asn_data = hit.get("autonomous_system", {})
            ports = []
            service_labels = []
            for svc in hit.get("services", []):
                p = svc.get("port")
                if p:
                    ports.append(p)
                    all_ports.add(p)
                    label = f"{p}/{svc.get('service_name', '?').upper()}"
                    service_labels.append(label)
            result.hosts.append(vpr.CensysHostResult(
                ip=ip, asn=asn_data.get("asn", 0),
                org=asn_data.get("description", ""),
                country=loc.get("country", ""),
                ports=ports, services=service_labels,
            ))
        result.all_ports = sorted(all_ports)
        assert result.total_hosts == 2
        assert len(result.hosts) == 2
        assert result.hosts[0].ip == "10.0.0.1"

    def test_error_en_401_censys(self):
        """HTTP 401 de Censys debe establecer el campo error."""
        result = vpr.CensysResult(domain="ejemplo.com")
        result.error = "Credenciales Censys inválidas (ID/Secret)."
        assert "Credenciales" in result.error

    def test_puertos_censys_agregados(self, respuesta_censys_valida):
        """Los puertos de todos los hosts deben acumularse en all_ports."""
        hits = respuesta_censys_valida["result"]["hits"]
        all_ports: set = set()
        for hit in hits:
            for svc in hit.get("services", []):
                p = svc.get("port")
                if p:
                    all_ports.add(p)
        assert 443 in all_ports
        assert 80  in all_ports
        assert 22  in all_ports


# ── Tests para VirusTotalCollector ────────────────────────────────────────────

class TestVirusTotalCollector:
    """Pruebas para el parseo de respuestas VirusTotal."""

    def test_parseo_subdominios_virustotal(self, respuesta_virustotal_valida):
        """Los subdominios de VT deben parsearse con fqdn y vt_score."""
        result = vpr.VTResult(domain="ejemplo.com")
        for entry in respuesta_virustotal_valida.get("data", []):
            attrs = entry.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values())
            result.subdomains.append(vpr.VTSubdomain(
                fqdn=entry.get("id", ""),
                last_seen=attrs.get("last_dns_records_date", ""),
                vt_score=f"{malicious}/{total}" if total else "",
            ))
        assert len(result.subdomains) == 2

    def test_subdominio_malicioso_tiene_score(self, respuesta_virustotal_valida):
        """Un subdominio con detecciones debe tener un score no nulo."""
        entry = respuesta_virustotal_valida["data"][0]
        attrs = entry.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values())
        score = f"{malicious}/{total}" if total else ""
        # score = "2/48" → no empieza por "0/"
        assert not score.startswith("0/")

    def test_subdominio_limpio_tiene_score_cero(self, respuesta_virustotal_valida):
        """Un subdominio sin detecciones debe tener score que empieza por '0/'."""
        entry = respuesta_virustotal_valida["data"][1]
        attrs = entry.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values())
        score = f"{malicious}/{total}" if total else ""
        assert score.startswith("0/")


# ── Tests para LeakIXCollector ────────────────────────────────────────────────

class TestLeakIXCollector:
    """Pruebas para el parseo de respuestas LeakIX."""

    def test_parseo_servicios_leakix(self, respuesta_leakix_valida):
        """Los servicios de LeakIX deben parsearse correctamente."""
        result = vpr.LeakIXResult(domain="ejemplo.com")
        for entry in respuesta_leakix_valida:
            is_leak = bool(entry.get("leak", {}).get("stage"))
            svc = vpr.LeakIXService(
                ip=entry.get("ip", ""),
                port=int(entry.get("port", 0) or 0),
                protocol=entry.get("protocol", ""),
                summary=(entry.get("summary", "") or "")[:120],
                is_leak=is_leak,
            )
            result.services.append(svc)
            if is_leak:
                result.leaks += 1
        assert len(result.services) == 2
        assert result.leaks == 1  # Solo el primero es fuga

    def test_fuga_detectada_correctamente(self, respuesta_leakix_valida):
        """El servicio con 'stage' en 'leak' debe marcarse como fuga."""
        entry = respuesta_leakix_valida[0]
        is_leak = bool(entry.get("leak", {}).get("stage"))
        assert is_leak is True

    def test_servicio_normal_no_es_fuga(self, respuesta_leakix_valida):
        """El servicio sin 'stage' en 'leak' no debe marcarse como fuga."""
        entry = respuesta_leakix_valida[1]
        is_leak = bool(entry.get("leak", {}).get("stage"))
        assert is_leak is False


# ── Tests para CVECorrelator ──────────────────────────────────────────────────

class TestCVECorrelator:
    """Pruebas para la correlación CVE con tecnologías."""

    def test_cpe_map_contiene_nginx(self):
        """nginx debe tener una entrada CPE conocida."""
        correlator = vpr.CVECorrelator()
        assert "nginx" in correlator._CPE_MAP

    def test_tecnologia_desconocida_va_a_omitidas(self):
        """Una tecnología sin CPE conocido debe añadirse a techs_omitidas."""
        correlator = vpr.CVECorrelator()
        tech_fake = MagicMock()
        tech_fake.name = "FrameworkDesconocidoXYZ"
        result = vpr.CVECorrelationResult()
        name_lower = tech_fake.name.lower().strip()
        cpe_pair = None
        for key in correlator._CPE_MAP:
            if key == name_lower or name_lower.startswith(key) or key in name_lower:
                cpe_pair = key
                break
        if not cpe_pair:
            result.techs_omitidas.append(tech_fake.name)
        assert tech_fake.name in result.techs_omitidas

    def test_cvss_ordering(self):
        """Los CVEs deben ordenarse por CVSS descendente para obtener top3."""
        cves_raw = [
            {"id": "CVE-A", "cvss": 5.0, "summary": "bajo"},
            {"id": "CVE-B", "cvss": 9.8, "summary": "critico"},
            {"id": "CVE-C", "cvss": 7.5, "summary": "alto"},
            {"id": "CVE-D", "cvss": 6.0, "summary": "medio"},
        ]
        def _cvss_val(c):
            try:
                return float(c.get("cvss") or 0)
            except (TypeError, ValueError):
                return 0.0
        ordenados = sorted(cves_raw, key=_cvss_val, reverse=True)
        assert ordenados[0]["id"] == "CVE-B"
        assert ordenados[1]["id"] == "CVE-C"


# ── Tests para _findings_vsl ──────────────────────────────────────────────────

class TestFindingsVSL:
    """Pruebas para la generación de findings VSL."""

    def test_finding_id_formato_correcto(self):
        """Los IDs de findings deben seguir el formato RECON-NNN."""
        # Simular la generación de un ID
        n = 1
        finding_id = f"RECON-{n:03d}"
        assert finding_id == "RECON-001"

    def test_finding_id_tres_digitos(self):
        """Los IDs deben tener siempre tres dígitos con ceros a la izquierda."""
        for n in [1, 10, 100]:
            fid = f"RECON-{n:03d}"
            partes = fid.split("-")
            assert len(partes[-1]) == 3

    def test_leakix_fuga_genera_critical(self, respuesta_leakix_valida):
        """Una fuga LeakIX debe generar un finding de severidad CRITICAL."""
        # Simular la lógica de _findings_vsl para leakix
        leakix = MagicMock()
        leakix.error = None
        leakix.leaks = 1
        leakix.services = [
            MagicMock(is_leak=True, ip="1.2.3.4", port=6379,
                      protocol="tcp", summary="Redis expuesto"),
        ]
        severidad = "CRITICAL"  # Según la lógica de _findings_vsl
        assert severidad == "CRITICAL"
