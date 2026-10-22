#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===============================================================================
PHP2Shell Enterprise Auditor & Reconnaissance Suite (CVE-2026-109618 / 109619)
===============================================================================
Auditor de seguridad no destructivo para verificar la exposición a las
vulnerabilidades críticas de PHP2Shell (RCE por OOM corruption y UAF de estado global)
en URLs de producción.

Marco de Exploración No Destructivo (OWASP / NIST SP 800-115 / OSSTMM):
- Evaluación pasiva y heurística de versión y umbrales de seguridad.
- Detección de Arquitectura y SAPI (Apache mod_php vs PHP-FPM vs LiteSpeed).
- Identificación de CMS y Frameworks (WordPress, Drupal, Joomla, Laravel, Symfony).
- Fingerprinting de Sistema Operativo y Distribución Linux (para evaluar backports).
- Detección de WAF, CDN y Proxies Inversos (Cloudflare, AWS WAF, Akamai, etc.).
- Verificación de Hardening y Fugas de Configuración (expose_php, cabeceras HSTS/CSP).
- Generación de reportes en Consola, JSON, CSV y Dashboard interactivo en HTML.
===============================================================================
"""

import argparse
import csv
import html
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# Constantes de Versiones Parcheadas (Security Releases Oficiales Octubre 2026)
PATCHED_VERSIONS = {
    8.5: (8, 5, 12),
    8.4: (8, 4, 27),
    8.3: (8, 3, 36),
    8.2: (8, 2, 35),
}

# Códigos de escape ANSI para terminal
class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


@dataclass
class AuditResult:
    url: str
    is_php: bool
    version_detected: Optional[str]
    status: str  # VULNERABLE, POTENTIALLY_VULNERABLE, PATCHED, NOT_PHP, ERROR
    severity: str  # CRITICAL, MEDIUM, LOW, INFO
    confidence: str  # HIGH, MEDIUM, LOW
    evidence: List[str] = field(default_factory=list)
    server_banner: str = ""
    status_code: Optional[int] = None
    os_detected: Optional[str] = None
    cms_detected: Optional[str] = None
    sapi_detected: Optional[str] = None
    waf_detected: Optional[str] = None
    hardening_issues: List[str] = field(default_factory=list)
    error_message: Optional[str] = None


class PHP2ShellAuditor:
    def __init__(
        self,
        timeout: int = 8,
        user_agent: Optional[str] = None,
        insecure: bool = False,
        proxy: Optional[str] = None,
        deep_scan: bool = False,
        verbose: bool = False,
    ):
        self.timeout = timeout
        self.user_agent = user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 "
            "(PHP2Shell-Audit/2.0)"
        )
        self.insecure = insecure
        self.proxy = proxy
        self.deep_scan = deep_scan
        self.verbose = verbose

        # Configuración SSL
        self.ssl_context = ssl.create_default_context()
        if self.insecure:
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE

    def _build_opener(self) -> urllib.request.OpenerDirector:
        handlers = []
        if self.insecure:
            handlers.append(urllib.request.HTTPSHandler(context=self.ssl_context))
        if self.proxy:
            handlers.append(
                urllib.request.ProxyHandler({"http": self.proxy, "https": self.proxy})
            )
        return urllib.request.build_opener(*handlers)

    def _send_request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        data: Optional[bytes] = None,
    ) -> Tuple[int, Dict[str, str], bytes]:
        req_headers = {"User-Agent": self.user_agent}
        if headers:
            req_headers.update(headers)

        req = urllib.request.Request(url, headers=req_headers, method=method, data=data)
        opener = self._build_opener()

        try:
            with opener.open(req, timeout=self.timeout) as resp:
                status = resp.status
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                body = resp.read(65536)  # Leer hasta 64KB para evitar sobrecarga de memoria
                return status, resp_headers, body
        except urllib.error.HTTPError as e:
            resp_headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
            body = e.read(16384) if hasattr(e, "read") else b""
            return e.code, resp_headers, body

    # -------------------------------------------------------------------------
    # Módulos de Fingerprinting No Destructivo
    # -------------------------------------------------------------------------

    @staticmethod
    def detect_os(server_banner: str, x_powered: str, body_text: str) -> Optional[str]:
        """Identifica el sistema operativo / distribución subyacente."""
        combined = f"{server_banner} {x_powered} {body_text}".lower()
        if "ubuntu" in combined:
            m = re.search(r"ubuntu[/\s]?([0-9]+\.[0-9]+)?", combined)
            return f"Ubuntu Linux {m.group(1)}" if m and m.group(1) else "Ubuntu Linux"
        if "debian" in combined:
            return "Debian GNU/Linux"
        if "centos" in combined:
            return "CentOS Linux"
        if "red hat" in combined or "rhel" in combined:
            return "Red Hat Enterprise Linux (RHEL)"
        if "almalinux" in combined or "rocky" in combined:
            return "AlmaLinux / Rocky Linux"
        if "alpine" in combined:
            return "Alpine Linux"
        if "win32" in combined or "win64" in combined or "windows" in combined or "microsoft-iis" in combined:
            return "Microsoft Windows Server"
        if "freebsd" in combined:
            return "FreeBSD"
        return None

    @staticmethod
    def detect_cms_and_framework(headers: Dict[str, str], body_text: str) -> Optional[str]:
        """Detecta CMS o Framework PHP mediante cabeceras, cookies y DOM."""
        set_cookie = headers.get("set-cookie", "").lower()
        x_generator = headers.get("x-generator", "").lower()
        x_powered = headers.get("x-powered-by", "").lower()
        body_lower = body_text.lower()

        # WordPress
        if (
            "wp-content" in body_lower
            or "wp-includes" in body_lower
            or "wordpress" in x_generator
            or "wordpress_" in set_cookie
            or "wp-settings-" in set_cookie
        ):
            return "WordPress"

        # Drupal
        if "drupal" in x_generator or "drupal.settings" in body_lower or "/sites/default/files" in body_lower:
            return "Drupal"

        # Joomla
        if "joomla" in x_generator or "joomla_" in set_cookie or "/components/com_" in body_lower:
            return "Joomla"

        # Laravel
        if "laravel_session" in set_cookie or "xsrf-token" in set_cookie:
            return "Laravel Framework"

        # Symfony
        if "symfony" in set_cookie or "_sf2_attributes" in set_cookie:
            return "Symfony Framework"

        # Moodle
        if "moodlesession" in set_cookie or "/theme/moodle" in body_lower:
            return "Moodle LMS"

        # Magento / Adobe Commerce
        if "mage.cookies" in body_lower or "/skin/frontend/" in body_lower or "frontend=" in set_cookie:
            return "Magento / Adobe Commerce"

        # PrestaShop
        if "prestashop" in x_powered or "prestashop-" in set_cookie or "prestashop" in body_lower:
            return "PrestaShop"

        return None

    @staticmethod
    def detect_sapi(server_banner: str, x_powered: str) -> Optional[str]:
        """
        Deduce la SAPI o arquitectura de ejecución de PHP.
        Relevancia crítica para CVE-2026-109618/19: Apache mod_php tiene exposición máxima.
        """
        banner_low = server_banner.lower()
        x_low = x_powered.lower()

        if "litespeed" in banner_low or "openlitespeed" in banner_low:
            return "LiteSpeed SAPI (LSPHP)"
        if "frankenphp" in banner_low:
            return "FrankenPHP (C-Go Worker Mode)"
        if "caddy" in banner_low:
            return "Caddy FastCGI"
        if "apache" in banner_low and ("php/" in banner_low or "mod_php" in banner_low):
            return "Apache mod_php (Intérprete Embebido - MÁXIMO RIESGO)"
        if "apache" in banner_low and "php" in x_low:
            return "Apache con PHP-FPM / FastCGI"
        if "nginx" in banner_low and ("php" in x_low or "phpsessid" in banner_low):
            return "Nginx Reverse Proxy + PHP-FPM"
        if "microsoft-iis" in banner_low:
            return "IIS FastCGI PHP"

        return None

    @staticmethod
    def detect_waf(headers: Dict[str, str]) -> Optional[str]:
        """Detecta la presencia de WAF, CDN o proxy inverso de protección."""
        server = headers.get("server", "").lower()

        if "cf-ray" in headers or "cf-cache-status" in headers or "cloudflare" in server:
            return "Cloudflare WAF / CDN"
        if "x-amz-cf-id" in headers or "x-amz-id-2" in headers or "cloudfront" in server:
            return "AWS CloudFront / AWS WAF"
        if "x-akamai-transformed" in headers or "akamaighost" in server:
            return "Akamai Edge Security"
        if "x-iinfo" in headers or "incap_ses" in headers.get("set-cookie", "").lower():
            return "Imperva Incapsula WAF"
        if "x-fastly-request-id" in headers or "fastly" in server:
            return "Fastly CDN"
        if "x-sucuri-id" in headers or "sucuri" in server:
            return "Sucuri CloudProxy WAF"

        return None

    @staticmethod
    def audit_hardening(url: str, headers: Dict[str, str], body_text: str) -> List[str]:
        """Evalúa las buenas prácticas de seguridad y hardening sin peticiones agresivas."""
        issues = []
        x_powered = headers.get("x-powered-by", "")
        server = headers.get("server", "")

        # 1. expose_php
        if "php" in x_powered.lower():
            issues.append("Directiva 'expose_php' ACTIVA (filtra versión en X-Powered-By)")

        # 2. Server Banner Verboso
        if re.search(r"apache/[0-9]+\.[0-9]+.*ubuntu|php/[0-9]", server, re.IGNORECASE):
            issues.append("Server banner divulga versión detallada y distribución de SO")

        # 3. Cabeceras de Seguridad en HTTPS
        if url.startswith("https://"):
            if "strict-transport-security" not in headers:
                issues.append("Falta cabecera HSTS (Strict-Transport-Security)")

        if "content-security-policy" not in headers:
            issues.append("Falta cabecera Content-Security-Policy (CSP)")

        if "x-frame-options" not in headers:
            issues.append("Falta cabecera X-Frame-Options (protección Clickjacking)")

        if headers.get("x-content-type-options", "").lower() != "nosniff":
            issues.append("Falta cabecera X-Content-Type-Options: nosniff")

        # 4. Fugas pasivas de errores nativos de PHP
        if "fatal error:" in body_text.lower() or "uncaught exception" in body_text.lower():
            issues.append("Directiva 'display_errors' ACTIVA (fuga rutas internas o errores nativos)")

        return issues

    @staticmethod
    def parse_version_tuple(ver_str: str) -> Optional[Tuple[int, int, int]]:
        """Extrae la tupla (major, minor, patch) de una cadena como '8.3.10' o '7.4.33-1+ubuntu'."""
        match = re.search(r"(\d+)\.(\d+)\.(\d+)", ver_str)
        if match:
            return int(match.group(1)), int(match.group(2)), int(match.group(3))
        match2 = re.search(r"(\d+)\.(\d+)", ver_str)
        if match2:
            return int(match2.group(1)), int(match2.group(2)), 0
        return None

    @classmethod
    def evaluate_php_version(cls, ver_str: str) -> Tuple[str, str, str]:
        """Evalúa si la versión de PHP detectada es vulnerable a CVE-2026-109618 / 109619."""
        v_tuple = cls.parse_version_tuple(ver_str)
        if not v_tuple:
            return (
                "POTENTIALLY_VULNERABLE",
                "MEDIUM",
                f"Versión de PHP detectada ({ver_str}) en formato no concluyente.",
            )

        major, minor, patch = v_tuple
        branch = float(f"{major}.{minor}")

        if branch in PATCHED_VERSIONS:
            p_major, p_minor, p_patch = PATCHED_VERSIONS[branch]
            if (major, minor, patch) >= (p_major, p_minor, p_patch):
                return (
                    "PATCHED",
                    "LOW",
                    f"PHP {major}.{minor}.{patch} es >= {p_major}.{p_minor}.{p_patch} (PARCHEADO frente a CVE-2026-109618/19).",
                )
            else:
                return (
                    "VULNERABLE",
                    "CRITICAL",
                    f"PHP {major}.{minor}.{patch} es menor que la versión corregida {p_major}.{p_minor}.{p_patch}.",
                )
        elif major < 8 or (major == 8 and minor < 2):
            return (
                "VULNERABLE",
                "CRITICAL",
                f"PHP {major}.{minor}.{patch} pertenece a una rama descontinuada (EOL). Afectado upstream sin parche oficial.",
            )
        else:
            return (
                "PATCHED",
                "LOW",
                f"PHP {major}.{minor}.{patch} pertenece a una rama superior a 8.5.",
            )

    def audit(self, url: str) -> AuditResult:
        """Audita una única URL con fingerprinting multi-módulo."""
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        evidence = []
        is_php = False
        detected_version: Optional[str] = None
        server_banner = ""

        try:
            status_code, headers, body = self._send_request(url, method="GET")
            server_banner = headers.get("server", "")

            body_text = ""
            try:
                body_text = body.decode("utf-8", errors="ignore")
            except Exception:
                pass

            # 1. Ejecutar Fingerprinting de Ecosistema
            os_detected = self.detect_os(server_banner, headers.get("x-powered-by", ""), body_text)
            cms_detected = self.detect_cms_and_framework(headers, body_text)
            waf_detected = self.detect_waf(headers)
            sapi_detected = self.detect_sapi(server_banner, headers.get("x-powered-by", ""))
            hardening_issues = self.audit_hardening(url, headers, body_text)

            # 2. Detección de PHP
            x_powered = headers.get("x-powered-by", "")
            if "php" in x_powered.lower():
                is_php = True
                evidence.append(f"Header 'X-Powered-By: {x_powered}'")
                v_match = re.search(r"PHP/([0-9]+\.[0-9]+(?:\.[0-9]+)?[\w.-]*)", x_powered, re.IGNORECASE)
                if v_match:
                    detected_version = v_match.group(1)

            if not detected_version and "php" in server_banner.lower():
                is_php = True
                evidence.append(f"Header 'Server: {server_banner}'")
                v_match = re.search(r"PHP/([0-9]+\.[0-9]+(?:\.[0-9]+)?[\w.-]*)", server_banner, re.IGNORECASE)
                if v_match:
                    detected_version = v_match.group(1)

            set_cookie = headers.get("set-cookie", "")
            if "phpsessid" in set_cookie.lower():
                is_php = True
                evidence.append("Cookie de sesión 'PHPSESSID' detectada en Set-Cookie")

            if re.search(r'href=["\'][^"\']+\.php(?:\?[^"\']*)?["\']', body_text, re.IGNORECASE):
                is_php = True
                evidence.append("Enlaces a archivos .php encontrados en el DOM")

            if cms_detected:
                is_php = True
                evidence.append(f"CMS/Framework PHP detectado: {cms_detected}")

            # 3. Sondas no intrusivas adicionales si la versión está oculta
            if not detected_version and is_php:
                easter_egg_url = urllib.parse.urljoin(url, "/?=PHPB8B5F2A0-8692-11d4-A2A1-003065CB33D7")
                try:
                    s_code, _, e_body = self._send_request(easter_egg_url, method="GET")
                    if s_code == 200 and (b"PHP Credits" in e_body or b"Zend Technologies" in e_body):
                        evidence.append("PHP Easter Egg (Credits) respondió afirmativamente")
                        v_credits = re.search(r"PHP Version\s+([0-9]+\.[0-9]+\.[0-9]+)", e_body.decode("utf-8", errors="ignore"))
                        if v_credits:
                            detected_version = v_credits.group(1)
                except Exception:
                    pass

            # 4. Escaneo profundo opcional (--deep)
            if self.deep_scan and not detected_version:
                deep_paths = ["/info.php", "/phpinfo.php", "/test.php", "/version.php"]
                for path in deep_paths:
                    probe_url = urllib.parse.urljoin(url, path)
                    try:
                        p_code, _, p_body = self._send_request(probe_url, method="GET")
                        if p_code == 200 and b"PHP Version" in p_body:
                            is_php = True
                            evidence.append(f"Archivo de diagnóstico expuesto detectado en {path}")
                            v_info = re.search(r"PHP Version\s*</td><td[^>]*>([0-9]+\.[0-9]+\.[0-9]+)", p_body.decode("utf-8", errors="ignore"))
                            if v_info:
                                detected_version = v_info.group(1)
                                break
                    except Exception:
                        continue

            # 5. Evaluación final de vulnerabilidad
            if detected_version:
                status, severity, desc = self.evaluate_php_version(detected_version)
                evidence.append(desc)
                if os_detected:
                    evidence.append(f"Sistema Operativo: {os_detected} (Verifique si aplica backports del distribuidor)")
                if sapi_detected:
                    evidence.append(f"Modo SAPI: {sapi_detected}")
                if waf_detected:
                    evidence.append(f"Protección perimetral: {waf_detected}")

                return AuditResult(
                    url=url,
                    is_php=True,
                    version_detected=detected_version,
                    status=status,
                    severity=severity,
                    confidence="HIGH",
                    evidence=evidence,
                    server_banner=server_banner,
                    status_code=status_code,
                    os_detected=os_detected,
                    cms_detected=cms_detected,
                    sapi_detected=sapi_detected,
                    waf_detected=waf_detected,
                    hardening_issues=hardening_issues,
                )
            elif is_php:
                evidence.append("PHP está en ejecución pero 'expose_php = Off' oculta la versión exacta.")
                if os_detected:
                    evidence.append(f"Sistema Operativo: {os_detected}")
                if sapi_detected:
                    evidence.append(f"Modo SAPI: {sapi_detected}")
                if waf_detected:
                    evidence.append(f"Protección perimetral: {waf_detected}")

                return AuditResult(
                    url=url,
                    is_php=True,
                    version_detected=None,
                    status="POTENTIALLY_VULNERABLE",
                    severity="MEDIUM",
                    confidence="MEDIUM",
                    evidence=evidence,
                    server_banner=server_banner,
                    status_code=status_code,
                    os_detected=os_detected,
                    cms_detected=cms_detected,
                    sapi_detected=sapi_detected,
                    waf_detected=waf_detected,
                    hardening_issues=hardening_issues,
                )
            else:
                return AuditResult(
                    url=url,
                    is_php=False,
                    version_detected=None,
                    status="NOT_PHP",
                    severity="INFO",
                    confidence="MEDIUM",
                    evidence=["No se identificaron firmas o cabeceras de entorno PHP."],
                    server_banner=server_banner,
                    status_code=status_code,
                    os_detected=os_detected,
                    cms_detected=cms_detected,
                    sapi_detected=sapi_detected,
                    waf_detected=waf_detected,
                    hardening_issues=hardening_issues,
                )

        except urllib.error.URLError as e:
            return AuditResult(
                url=url,
                is_php=False,
                version_detected=None,
                status="ERROR",
                severity="LOW",
                confidence="LOW",
                evidence=[f"Fallo de conexión de red: {str(e.reason)}"],
                server_banner="",
                status_code=None,
                error_message=str(e.reason),
            )
        except Exception as e:
            return AuditResult(
                url=url,
                is_php=False,
                version_detected=None,
                status="ERROR",
                severity="LOW",
                confidence="LOW",
                evidence=[f"Error inesperado al auditar: {str(e)}"],
                server_banner="",
                status_code=None,
                error_message=str(e),
            )


# -----------------------------------------------------------------------------
# Generador de Reportes HTML Interactivo (Zero-Dependencies)
# -----------------------------------------------------------------------------

def generate_html_report(results: List[AuditResult], elapsed_time: float, output_path: str):
    """Genera un reporte interactivo moderno en HTML para auditorías de ciberseguridad."""
    total = len(results)
    vuln = sum(1 for r in results if r.status == "VULNERABLE")
    pot = sum(1 for r in results if r.status == "POTENTIALLY_VULNERABLE")
    patched = sum(1 for r in results if r.status == "PATCHED")
    not_php = sum(1 for r in results if r.status == "NOT_PHP")
    err = sum(1 for r in results if r.status == "ERROR")

    rows = []
    for r in results:
        status_class = {
            "VULNERABLE": "badge-danger",
            "POTENTIALLY_VULNERABLE": "badge-warning",
            "PATCHED": "badge-success",
            "NOT_PHP": "badge-info",
            "ERROR": "badge-secondary",
        }.get(r.status, "badge-secondary")

        status_label = {
            "VULNERABLE": "CRÍTICO: VULNERABLE",
            "POTENTIALLY_VULNERABLE": "POTENCIALMENTE EXPUESTO",
            "PATCHED": "SEGURO / PARCHEADO",
            "NOT_PHP": "NO PHP",
            "ERROR": "ERROR DE RED",
        }.get(r.status, r.status)

        ev_html = "".join(f"<li>{html.escape(e)}</li>" for e in r.evidence)
        hard_html = (
            "".join(f"<li class='text-warn'>{html.escape(h)}</li>" for h in r.hardening_issues)
            if r.hardening_issues
            else "<span class='text-muted'>Sin hallazgos pasivos</span>"
        )

        rows.append(f"""
        <tr>
            <td><strong>{html.escape(r.url)}</strong><br><small class="text-muted">{html.escape(r.server_banner or 'N/A')}</small></td>
            <td><span class="badge {status_class}">{status_label}</span></td>
            <td><strong>{html.escape(r.version_detected or 'No divulgada')}</strong></td>
            <td>{html.escape(r.cms_detected or 'Genérico')}</td>
            <td>{html.escape(r.sapi_detected or 'Desconocido')}</td>
            <td>{html.escape(r.os_detected or 'No identificado')}</td>
            <td>{html.escape(r.waf_detected or 'Directo / Ninguno')}</td>
            <td><ul class="ev-list">{ev_html}</ul></td>
            <td><ul class="ev-list">{hard_html}</ul></td>
        </tr>
        """)

    html_content = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PHP2Shell Security Audit Dashboard</title>
    <style>
        :root {{
            --bg: #0f172a;
            --surface: #1e293b;
            --border: #334155;
            --text: #f8fafc;
            --text-muted: #94a3b8;
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #10b981;
            --info: #06b6d4;
            --primary: #3b82f6;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            padding: 24px;
            line-height: 1.5;
        }}
        .header {{
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            border: 1px solid var(--border);
            padding: 24px;
            border-radius: 12px;
            margin-bottom: 24px;
        }}
        .header h1 {{ font-size: 1.8rem; margin-bottom: 8px; color: #fff; }}
        .header p {{ color: var(--text-muted); font-size: 0.95rem; }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .stat-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            padding: 16px;
            border-radius: 10px;
            text-align: center;
        }}
        .stat-card h3 {{ font-size: 0.85rem; text-transform: uppercase; color: var(--text-muted); margin-bottom: 6px; }}
        .stat-card .value {{ font-size: 2rem; font-weight: bold; }}
        .val-danger {{ color: var(--danger); }}
        .val-warning {{ color: var(--warning); }}
        .val-success {{ color: var(--success); }}
        .val-info {{ color: var(--info); }}
        .val-muted {{ color: var(--text-muted); }}

        .table-container {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            overflow-x: auto;
            margin-bottom: 24px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
            text-align: left;
        }}
        th, td {{
            padding: 14px 16px;
            border-bottom: 1px solid var(--border);
            vertical-align: top;
        }}
        th {{
            background: rgba(0, 0, 0, 0.2);
            color: var(--text-muted);
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.5px;
        }}
        tr:hover {{ background: rgba(255, 255, 255, 0.02); }}
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 600;
        }}
        .badge-danger {{ background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid var(--danger); }}
        .badge-warning {{ background: rgba(245, 158, 11, 0.2); color: #fde68a; border: 1px solid var(--warning); }}
        .badge-success {{ background: rgba(16, 185, 129, 0.2); color: #6ee7b7; border: 1px solid var(--success); }}
        .badge-info {{ background: rgba(6, 182, 212, 0.2); color: #a5f3fc; border: 1px solid var(--info); }}
        .badge-secondary {{ background: rgba(148, 163, 184, 0.2); color: #cbd5e1; border: 1px solid var(--text-muted); }}
        .ev-list {{ list-style-type: none; font-size: 0.8rem; color: var(--text-muted); }}
        .ev-list li {{ margin-bottom: 4px; }}
        .text-warn {{ color: #fde68a; }}
        .text-muted {{ color: var(--text-muted); }}
        .footer {{
            text-align: center;
            font-size: 0.85rem;
            color: var(--text-muted);
            padding: 16px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Dashboard de Auditoría: PHP2Shell (CVE-2026-109618 / 109619)</h1>
        <p>Evaluación de ciberseguridad no destructiva | Umbrales de mitigación: PHP >= 8.2.35, 8.3.36, 8.4.27, 8.5.12</p>
    </div>

    <div class="stats-grid">
        <div class="stat-card">
            <h3>Total Objetivos</h3>
            <div class="value val-muted">{total}</div>
        </div>
        <div class="stat-card">
            <h3>Vulnerables</h3>
            <div class="value val-danger">{vuln}</div>
        </div>
        <div class="stat-card">
            <h3>Potencialmente Expuestos</h3>
            <div class="value val-warning">{pot}</div>
        </div>
        <div class="stat-card">
            <h3>Parcheados / Seguros</h3>
            <div class="value val-success">{patched}</div>
        </div>
        <div class="stat-card">
            <h3>No es PHP</h3>
            <div class="value val-info">{not_php}</div>
        </div>
    </div>

    <div class="table-container">
        <table>
            <thead>
                <tr>
                    <th>URL / Servidor</th>
                    <th>Estado</th>
                    <th>Versión PHP</th>
                    <th>CMS / Framework</th>
                    <th>SAPI / Arquitectura</th>
                    <th>Sistema Operativo</th>
                    <th>WAF / CDN</th>
                    <th>Evidencia</th>
                    <th>Hallazgos Hardening</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
        </table>
    </div>

    <div class="footer">
        Auditoría completada en {elapsed_time:.2f} segundos. Generado automáticamente por PHP2Shell Enterprise Auditor.
    </div>
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)


def format_status_badge(status: str) -> str:
    if status == "VULNERABLE":
        return f"{Colors.BOLD}{Colors.RED}[CRÍTICO: VULNERABLE]{Colors.RESET}"
    elif status == "POTENTIALLY_VULNERABLE":
        return f"{Colors.BOLD}{Colors.YELLOW}[ALERTA: POTENCIALMENTE VULNERABLE]{Colors.RESET}"
    elif status == "PATCHED":
        return f"{Colors.BOLD}{Colors.GREEN}[SEGURO: PARCHEADO]{Colors.RESET}"
    elif status == "NOT_PHP":
        return f"{Colors.CYAN}[NO DETECTADO PHP]{Colors.RESET}"
    else:
        return f"{Colors.MAGENTA}[ERROR / INACCESIBLE]{Colors.RESET}"


def print_banner():
    banner = f"""
{Colors.CYAN}╔═════════════════════════════════════════════════════════════════════════════════╗
║   PHP2Shell Enterprise Reconnaissance Suite (CVE-2026-109618 / CVE-2026-109619) ║
║         Auditoría No Destructiva • CMS • SAPI • OS • WAF • Hardening            ║
╚═════════════════════════════════════════════════════════════════════════════════╝{Colors.RESET}
"""
    print(banner)


def main():
    parser = argparse.ArgumentParser(
        description="Auditor empresarial no destructivo para CVE-2026-109618 / CVE-2026-109619 (PHP2Shell)"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", type=str, help="URL individual para auditar (ej. https://example.com)")
    group.add_argument("-f", "--file", type=str, help="Archivo de texto con lista de URLs (una por línea)")

    parser.add_argument("-t", "--threads", type=int, default=5, help="Número de hilos concurrentes (default: 5)")
    parser.add_argument("--timeout", type=int, default=8, help="Timeout HTTP en segundos (default: 8)")
    parser.add_argument("--user-agent", type=str, default=None, help="User-Agent personalizado")
    parser.add_argument("-k", "--insecure", action="store_true", help="Ignorar errores de validación de certificados SSL")
    parser.add_argument("--proxy", type=str, default=None, help="Proxy HTTP/HTTPS (ej. http://127.0.0.1:8080)")
    parser.add_argument("--deep", action="store_true", help="Realizar sondeo profundo no invasivo (rutas info/diagnóstico)")
    parser.add_argument("-oJ", "--output-json", type=str, default=None, help="Ruta de archivo para guardar reporte en JSON")
    parser.add_argument("-oC", "--output-csv", type=str, default=None, help="Ruta de archivo para guardar reporte en CSV")
    parser.add_argument("-oH", "--output-html", type=str, default=None, help="Ruta para generar Dashboard interactivo en HTML")
    parser.add_argument("-q", "--quiet", action="store_true", help="Modo silencioso, solo muestra resultados directos")

    args = parser.parse_args()

    if not args.quiet:
        print_banner()

    urls: List[str] = []
    if args.url:
        urls.append(args.url.strip())
    elif args.file:
        if not os.path.exists(args.file):
            print(f"{Colors.RED}[!] Error: Archivo no encontrado: {args.file}{Colors.RESET}", file=sys.stderr)
            sys.exit(1)
        with open(args.file, "r", encoding="utf-8") as f:
            for line in f:
                cleaned = line.strip()
                if cleaned and not cleaned.startswith("#"):
                    urls.append(cleaned)

    if not urls:
        print(f"{Colors.RED}[!] No se especificaron URLs válidas para auditar.{Colors.RESET}")
        sys.exit(1)

    auditor = PHP2ShellAuditor(
        timeout=args.timeout,
        user_agent=args.user_agent,
        insecure=args.insecure,
        proxy=args.proxy,
        deep_scan=args.deep,
    )

    if not args.quiet:
        print(f"[*] Iniciando auditoría sobre {len(urls)} objetivo(s) con {args.threads} hilo(s)...")
        print(f"[*] Módulos activos: Versión, CMS/Framework, SAPI, Sistema Operativo, WAF/CDN, Hardening")
        print(f"{'-' * 80}\n")

    results: List[AuditResult] = []
    stats = {
        "VULNERABLE": 0,
        "POTENTIALLY_VULNERABLE": 0,
        "PATCHED": 0,
        "NOT_PHP": 0,
        "ERROR": 0,
    }

    start_time = time.time()

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_url = {executor.submit(auditor.audit, u): u for u in urls}
        for future in as_completed(future_to_url):
            res = future.result()
            results.append(res)
            stats[res.status] = stats.get(res.status, 0) + 1

            badge = format_status_badge(res.status)
            ver_info = f"(PHP {res.version_detected})" if res.version_detected else ""
            status_http = f"HTTP {res.status_code}" if res.status_code else "NO_RESP"

            print(f"{badge} {res.url} {ver_info} [{status_http}]")
            if not args.quiet:
                # Mostrar contexto de reconocimiento
                details = []
                if res.cms_detected:
                    details.append(f"CMS/App: {res.cms_detected}")
                if res.sapi_detected:
                    details.append(f"SAPI: {res.sapi_detected}")
                if res.os_detected:
                    details.append(f"SO: {res.os_detected}")
                if res.waf_detected:
                    details.append(f"WAF: {res.waf_detected}")

                if details:
                    print(f"    ├─ {Colors.CYAN}Reconocimiento: {' | '.join(details)}{Colors.RESET}")

                if res.evidence:
                    for ev in res.evidence:
                        print(f"    ├─ {Colors.WHITE}{ev}{Colors.RESET}")

                if res.hardening_issues:
                    for h in res.hardening_issues:
                        print(f"    └─ {Colors.YELLOW}[Hardening] {h}{Colors.RESET}")

    elapsed = time.time() - start_time

    if not args.quiet:
        print(f"\n{'-' * 80}")
        print(f"{Colors.BOLD}Resumen de Auditoría PHP2Shell:{Colors.RESET}")
        print(f"  {Colors.RED}● Vulnerables Confirmados : {stats['VULNERABLE']}{Colors.RESET}")
        print(f"  {Colors.YELLOW}● Potencialmente Expuestos : {stats['POTENTIALLY_VULNERABLE']} (PHP detectado, versión oculta){Colors.RESET}")
        print(f"  {Colors.GREEN}● Parcheados / Seguros    : {stats['PATCHED']}{Colors.RESET}")
        print(f"  {Colors.CYAN}● No es PHP               : {stats['NOT_PHP']}{Colors.RESET}")
        print(f"  {Colors.MAGENTA}● Errores / Inaccesibles  : {stats['ERROR']}{Colors.RESET}")
        print(f"  Tiempo total transcurrido : {elapsed:.2f} segundos")
        print(f"{'-' * 80}\n")

    # Exportación a JSON
    if args.output_json:
        try:
            with open(args.output_json, "w", encoding="utf-8") as jf:
                json.dump([asdict(r) for r in results], jf, indent=2, ensure_ascii=False)
            if not args.quiet:
                print(f"[+] Reporte JSON guardado en: {args.output_json}")
        except Exception as e:
            print(f"{Colors.RED}[!] Error al escribir JSON: {e}{Colors.RESET}", file=sys.stderr)

    # Exportación a CSV
    if args.output_csv:
        try:
            with open(args.output_csv, "w", newline="", encoding="utf-8") as cf:
                writer = csv.writer(cf)
                writer.writerow([
                    "URL",
                    "Is_PHP",
                    "Version_Detected",
                    "Status",
                    "Severity",
                    "Confidence",
                    "CMS_Framework",
                    "SAPI_Architecture",
                    "Operating_System",
                    "WAF_CDN",
                    "Server_Banner",
                    "HTTP_Status",
                    "Hardening_Issues",
                    "Evidence",
                ])
                for r in results:
                    writer.writerow([
                        r.url,
                        r.is_php,
                        r.version_detected or "N/A",
                        r.status,
                        r.severity,
                        r.confidence,
                        r.cms_detected or "",
                        r.sapi_detected or "",
                        r.os_detected or "",
                        r.waf_detected or "",
                        r.server_banner,
                        r.status_code or "",
                        " | ".join(r.hardening_issues),
                        " | ".join(r.evidence),
                    ])
            if not args.quiet:
                print(f"[+] Reporte CSV guardado en: {args.output_csv}")
        except Exception as e:
            print(f"{Colors.RED}[!] Error al escribir CSV: {e}{Colors.RESET}", file=sys.stderr)

    # Exportación a HTML Dashboard
    if args.output_html:
        try:
            generate_html_report(results, elapsed, args.output_html)
            if not args.quiet:
                print(f"[+] Dashboard interactivo HTML generado en: {args.output_html}")
        except Exception as e:
            print(f"{Colors.RED}[!] Error al escribir HTML: {e}{Colors.RESET}", file=sys.stderr)


if __name__ == "__main__":
    main()
