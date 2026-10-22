#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===============================================================================
PHP2Shell Production Auditor (CVE-2026-109618 & CVE-2026-109619)
===============================================================================
Auditor de seguridad no destructivo para verificar la exposición a las
vulnerabilidades críticas de PHP2Shell (RCE por OOM corruption y UAF de estado global)
en URLs de producción.

Uso seguro en producción:
- NO ejecuta payloads de sobrecarga de memoria (OOM DoS) que puedan tumbar workers PHP-FPM / Apache.
- Evalúa fingerprinting pasivo de versión, cabeceras HTTP, cookies de sesión y
  heurísticas no intrusivas.
- Clasifica el nivel de riesgo con alta precisión y genera reportes en JSON/CSV.
===============================================================================
"""

import argparse
import csv
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
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple

# Constantes de Versiones Parcheadas (Security Releases Octubre 2026)
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
    RESET = "\033[0m"


@dataclass
class AuditResult:
    url: str
    is_php: bool
    version_detected: Optional[str]
    status: str  # VULNERABLE, POTENTIALLY_VULNERABLE, PATCHED, NOT_PHP, ERROR
    severity: str  # CRITICAL, MEDIUM, LOW, INFO
    confidence: str  # HIGH, MEDIUM, LOW
    evidence: List[str]
    server_banner: str
    status_code: Optional[int]
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
            "(PHP2Shell-Audit/1.0)"
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
                body = resp.read(65536)  # Leer hasta 64KB para evitar sobrecarga
                return status, resp_headers, body
        except urllib.error.HTTPError as e:
            resp_headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
            body = e.read(16384) if hasattr(e, "read") else b""
            return e.code, resp_headers, body

    @staticmethod
    def parse_version_tuple(ver_str: str) -> Optional[Tuple[int, int, int]]:
        """Extrae la tupla (major, minor, patch) de una cadena como '8.3.10' o '7.4.33-1+ubuntu'."""
        match = re.search(r"(\d+)\.(\d+)\.(\d+)", ver_str)
        if match:
            return int(match.group(1)), int(match.group(2)), int(match.group(3))
        # Para versiones como 8.3
        match2 = re.search(r"(\d+)\.(\d+)", ver_str)
        if match2:
            return int(match2.group(1)), int(match2.group(2)), 0
        return None

    @classmethod
    def evaluate_php_version(cls, ver_str: str) -> Tuple[str, str, str]:
        """
        Evalúa si la versión de PHP detectada es vulnerable a CVE-2026-109618 / 109619.
        Retorna (status, severity, description).
        """
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
                    f"PHP {major}.{minor}.{patch} es >= {p_major}.{p_minor}.{p_patch} (PARCHEADO con mitigación CVE-2026-109618/19).",
                )
            else:
                return (
                    "VULNERABLE",
                    "CRITICAL",
                    f"PHP {major}.{minor}.{patch} es menor que la versión corregida {p_major}.{p_minor}.{p_patch}.",
                )
        elif major < 8 or (major == 8 and minor < 2):
            # Versiones EOL (<= 8.1): sin soporte oficial de seguridad upstream
            return (
                "VULNERABLE",
                "CRITICAL",
                f"PHP {major}.{minor}.{patch} pertenece a una rama descontinuada (EOL). Afectado upstream sin parche oficial.",
            )
        else:
            # Versiones futuras o branches > 8.5
            return (
                "PATCHED",
                "LOW",
                f"PHP {major}.{minor}.{patch} pertenece a una rama superior a 8.5.",
            )

    def audit(self, url: str) -> AuditResult:
        """Audita una única URL para detectar PHP y vulnerabilidad a PHP2Shell."""
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        evidence = []
        is_php = False
        detected_version: Optional[str] = None
        server_banner = ""

        try:
            # 1. Petición base inicial a la URL
            status_code, headers, body = self._send_request(url, method="GET")
            server_banner = headers.get("server", "")

            # A. Revisar X-Powered-By
            x_powered = headers.get("x-powered-by", "")
            if "php" in x_powered.lower():
                is_php = True
                evidence.append(f"Header 'X-Powered-By: {x_powered}'")
                v_match = re.search(r"PHP/([0-9]+\.[0-9]+(?:\.[0-9]+)?[\w.-]*)", x_powered, re.IGNORECASE)
                if v_match:
                    detected_version = v_match.group(1)

            # B. Revisar Server header
            if not detected_version and "php" in server_banner.lower():
                is_php = True
                evidence.append(f"Header 'Server: {server_banner}'")
                v_match = re.search(r"PHP/([0-9]+\.[0-9]+(?:\.[0-9]+)?[\w.-]*)", server_banner, re.IGNORECASE)
                if v_match:
                    detected_version = v_match.group(1)

            # C. Revisar cookies de sesión (PHPSESSID)
            set_cookie = headers.get("set-cookie", "")
            if "phpsessid" in set_cookie.lower():
                is_php = True
                evidence.append("Cookie de sesión 'PHPSESSID' detectada en Set-Cookie")

            # D. Heurística de cuerpo y enlaces a scripts .php
            body_text = ""
            try:
                body_text = body.decode("utf-8", errors="ignore")
            except Exception:
                pass

            if re.search(r'href=["\'][^"\']+\.php(?:\?[^"\']*)?["\']', body_text, re.IGNORECASE):
                is_php = True
                evidence.append("Enlaces a archivos .php encontrados en el DOM")

            if "php fatal error" in body_text.lower() or "php warning" in body_text.lower():
                is_php = True
                evidence.append("Mensajes de error nativos de PHP detectados en la respuesta")
                v_err = re.search(r"PHP\s+([0-9]+\.[0-9]+\.[0-9]+)", body_text)
                if v_err and not detected_version:
                    detected_version = v_err.group(1)

            # E. Sondas no intrusivas adicionales si PHP no se confirmó o la versión está oculta
            if not detected_version and is_php:
                # Sonda no destructiva de PHP Easter Egg (expuesto en versiones antiguas o configs heredadas)
                easter_egg_url = urllib.parse.urljoin(url, "/?=PHPB8B5F2A0-8692-11d4-A2A1-003065CB33D7")
                try:
                    s_code, e_headers, e_body = self._send_request(easter_egg_url, method="GET")
                    if s_code == 200 and (b"PHP Credits" in e_body or b"Zend Technologies" in e_body):
                        evidence.append("PHP Easter Egg (Credits) respondió afirmativamente")
                        v_credits = re.search(r"PHP Version\s+([0-9]+\.[0-9]+\.[0-9]+)", e_body.decode("utf-8", errors="ignore"))
                        if v_credits:
                            detected_version = v_credits.group(1)
                except Exception:
                    pass

            # F. Escaneo profundo opcional (--deep) de rutas de información administrativa comunes
            if self.deep_scan and not detected_version:
                deep_paths = ["/info.php", "/phpinfo.php", "/test.php", "/version.php"]
                for path in deep_paths:
                    probe_url = urllib.parse.urljoin(url, path)
                    try:
                        p_code, _, p_body = self._send_request(probe_url, method="GET")
                        if p_code == 200 and b"PHP Version" in p_body:
                            is_php = True
                            evidence.append(f"Archivo expuesto detectado en {path}")
                            v_info = re.search(r"PHP Version\s*</td><td[^>]*>([0-9]+\.[0-9]+\.[0-9]+)", p_body.decode("utf-8", errors="ignore"))
                            if v_info:
                                detected_version = v_info.group(1)
                                break
                    except Exception:
                        continue

            # Evaluación final de vulnerabilidad
            if detected_version:
                status, severity, desc = self.evaluate_php_version(detected_version)
                evidence.append(desc)
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
                )
            elif is_php:
                evidence.append("PHP está en ejecución pero 'expose_php = Off' oculta la versión exacta.")
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
{Colors.CYAN}╔═══════════════════════════════════════════════════════════════════════════╗
║   PHP2Shell Production URL Auditor (CVE-2026-109618 / CVE-2026-109619)   ║
║      Auditoría Segura y No Destructiva para Entornos de Producción        ║
╚═══════════════════════════════════════════════════════════════════════════╝{Colors.RESET}
"""
    print(banner)


def main():
    parser = argparse.ArgumentParser(
        description="Auditor de URLs en producción para CVE-2026-109618 / CVE-2026-109619 (PHP2Shell)"
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
    parser.add_argument("-q", "--quiet", action="store_true", help="Modo silencioso, solo muestra resultados directos")

    args = parser.parse_args()

    if not args.quiet:
        print_banner()

    # Obtener lista de URLs
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
        print(f"[*] Umbrales parcheados: PHP >= 8.2.35, 8.3.36, 8.4.27, 8.5.12")
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

            # Salida en consola
            badge = format_status_badge(res.status)
            ver_info = f"(PHP {res.version_detected})" if res.version_detected else ""
            status_http = f"HTTP {res.status_code}" if res.status_code else "NO_RESP"

            print(f"{badge} {res.url} {ver_info} [{status_http}]")
            if not args.quiet and res.evidence:
                for ev in res.evidence:
                    print(f"    ├─ {Colors.WHITE}{ev}{Colors.RESET}")

    elapsed = time.time() - start_time

    # Resumen en consola
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

        if stats["VULNERABLE"] > 0 or stats["POTENTIALLY_VULNERABLE"] > 0:
            print(f"{Colors.BOLD}{Colors.RED}[!] ACCIÓN RECOMENDADA:{Colors.RESET}")
            print("  1. Actualice inmediatamente los runtimes de PHP a las versiones seguras:")
            print("     - PHP 8.5 -> 8.5.12+")
            print("     - PHP 8.4 -> 8.4.27+")
            print("     - PHP 8.3 -> 8.3.36+")
            print("     - PHP 8.2 -> 8.2.35+")
            print("  2. Si usa PHP 8.1 o inferior (EOL), migre urgentemente o aplique parches de soporte extendido.")
            print("  3. REINICIE los procesos de workers (PHP-FPM, Apache mod_php, contenedores Docker) tras actualizar.")
            print("  4. En producción, configure 'expose_php = Off' en php.ini para evitar enumeración.")

    # Guardar en JSON si se solicitó
    if args.output_json:
        try:
            with open(args.output_json, "w", encoding="utf-8") as jf:
                json.dump([asdict(r) for r in results], jf, indent=2, ensure_ascii=False)
            if not args.quiet:
                print(f"[+] Reporte JSON guardado en: {args.output_json}")
        except Exception as e:
            print(f"{Colors.RED}[!] Error al escribir JSON: {e}{Colors.RESET}", file=sys.stderr)

    # Guardar en CSV si se solicitó
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
                    "Server_Banner",
                    "HTTP_Status",
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
                        r.server_banner,
                        r.status_code or "",
                        " | ".join(r.evidence),
                    ])
            if not args.quiet:
                print(f"[+] Reporte CSV guardado en: {args.output_csv}")
        except Exception as e:
            print(f"{Colors.RED}[!] Error al escribir CSV: {e}{Colors.RESET}", file=sys.stderr)


if __name__ == "__main__":
    main()
