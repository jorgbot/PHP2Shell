# PHP2Shell Enterprise Reconnaissance & Audit Suite

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0%20(stdlib%20only)-brightgreen.svg)]()
[![CVEs](https://img.shields.io/badge/CVE-2026--109618%20%7C%20CVE--2026--109619-red.svg)]()
[![Standard: SARIF](https://img.shields.io/badge/SARIF-OASIS%20v2.1.0-purple.svg)]()
[![CI/CD: GitHub Actions](https://img.shields.io/badge/CI%2FCD-GitHub%20Actions-blue.svg)](.github/workflows/security-audit.yml)
[![Methodology](https://img.shields.io/badge/Framework-OWASP%20%7C%20NIST%20SP%20800--115-orange.svg)]()

Suite de auditoría remota y local, segura y **no destructiva** diseñada para escanear y evaluar la exposición de activos de producción a las vulnerabilidades críticas del core de PHP conocidas como **PHP2Shell** (**CVE-2026-109618** y **CVE-2026-109619**), incorporando fingerprinting de ecosistema, detección de SAPI, CMS, WAF, Sistema Operativo, inspección de certificados SSL/TLS, auditoría de `php.ini`, integración con GitHub Code Scanning (SARIF) y alertas vía Webhooks.

---

## 1. Contexto de las Vulnerabilidades

* **CVE-2026-109618 (RCE vía Out-Of-Memory / OOM Corruption):**
  PHP utiliza `longjmp()` para gestionar excepciones de agotamiento de memoria (OOM). Si la salida abrupta ocurre mientras ciertas estructuras internas están en proceso de inicialización, la rutina de limpieza posterior intenta leer o desviar la ejecución basándose en memoria no inicializada, permitiendo ejecución remota de código (RCE) sin autenticación.
* **CVE-2026-109619 (RCE vía Stale Global State / Use-After-Free):**
  Bajo condiciones específicas de fallo fatal o finalización de petición, punteros globales temporales mantienen referencias a memoria liberada de la petición anterior. Al ser reutilizado el worker (en entornos como PHP-FPM o Apache `mod_php`), la petición subsiguiente desencadena una condición Use-After-Free explotable.

### Umbrales de Versiones Parcheadas (Upstream Releases)
| Rama PHP | Versión Mínima Segura (Parcheada) | Estado Previo |
| :--- | :--- | :--- |
| **PHP 8.5** | **`8.5.12`** o superior | `< 8.5.12` es **Vulnerable** |
| **PHP 8.4** | **`8.4.27`** o superior | `< 8.4.27` es **Vulnerable** |
| **PHP 8.3** | **`8.3.36`** o superior | `< 8.3.36` es **Vulnerable** |
| **PHP 8.2** | **`8.2.35`** o superior | `< 8.2.35` es **Vulnerable** |
| **PHP <= 8.1** | *Rama EOL (Sin soporte upstream)* | **Crítico / Vulnerable por defecto** *(Requiere migración o parche ELS)* |

---

## 2. Capacidades de la Suite

El auditor opera bajo estándares de exploración defensiva (**NIST SP 800-115**, **OWASP WSTG**, **OSSTMM**):

1. **Detección de SAPI y Arquitectura:**
   - Identifica si el entorno corre sobre **Apache `mod_php`** (máximo riesgo en PHP2Shell al estar embebido en el proceso HTTP), **Nginx + PHP-FPM**, **LiteSpeed (LSPHP)** o **FrankenPHP**.
2. **Detección de CMS y Frameworks:**
   - Reconocimiento pasivo de WordPress, Drupal, Joomla, Laravel, Symfony, Magento, PrestaShop y Moodle.
3. **Fingerprinting de Sistema Operativo y Distribución:**
   - Identifica Ubuntu, Debian, CentOS, RHEL, Alpine o Windows Server para contextualizar si el sistema aplica parches retrocompatibles (*backports*).
4. **Detección de WAF y CDN:**
   - Identifica proxies y firewalls perimetrales (Cloudflare, AWS WAF/CloudFront, Akamai, Imperva, Fastly, Sucuri).
5. **Inspección Pasiva de Certificados SSL/TLS:**
   - Extrae versión de TLS, cifrado, emisor (Let's Encrypt, DigiCert, etc.) y días restantes de vigencia.
6. **Auditoría Local de Servidor / Contenedor (`--audit-local`):**
   - Audita el archivo `php.ini` y runtime local evaluando `memory_limit`, `disable_functions` (funciones de ejecución de comandos), `expose_php` y `display_errors`.
7. **Exportación Estándar OASIS SARIF v2.1.0 (`-oS`):**
   - Compatible nativamente con la pestaña **Security -> Code Scanning** de GitHub.
8. **Alertas Webhook (`--webhook`):**
   - Despacho inmediato de alertas a canales de Slack, Discord, Microsoft Teams o plataformas SIEM/SOC.
9. **Dashboard Interactivo en HTML (`-oH`):**
   - Generación de reportes ejecutivos con estadísticas, tablas responsivas y filtrado de severidad sin dependencias externas.

---

## 3. Instalación

### Prerrequisitos
- Python 3.8 o superior (`python3 --version`).
- **Cero dependencias externas:** Utiliza exclusivamente librerías estándar de Python (`urllib`, `ssl`, `json`, `csv`, `concurrent.futures`, `re`, `argparse`, `html`, `socket`, `subprocess`).

### Clonar el repositorio
```bash
git clone https://github.com/jorgbot/PHP2Shell.git
cd PHP2Shell
chmod +x audit_php2shell.py
```

### (Opcional) Instalar como comando CLI global
```bash
pip install .
# Ejecutable directamente como:
php2shell-audit -u https://ejemplo.com
```

---

## 4. Ejemplos de Uso

### A. Auditoría Remota de una URL Individual
```bash
python3 audit_php2shell.py -u https://midominio.com
```

### B. Auditoría Local de Servidor o Contenedor Docker
```bash
python3 audit_php2shell.py --audit-local
# O especificando un archivo php.ini específico:
python3 audit_php2shell.py --audit-local --ini /etc/php/8.3/fpm/php.ini
```

### C. Auditoría Masiva con Reporte Completo (HTML + JSON + CSV + SARIF)
```bash
python3 audit_php2shell.py -f targets_example.txt -t 10 \
  -oH dashboard.html \
  -oJ reporte.json \
  -oC reporte.csv \
  -oS results.sarif
```

### D. Notificación Automática a Webhook de Slack / Discord
```bash
python3 audit_php2shell.py -f targets_example.txt --webhook https://hooks.slack.com/services/XXX/YYY/ZZZ
```

---

## 5. Parámetros Disponibles

```text
  -u, --url URL             URL individual para auditar.
  -f, --file FILE           Archivo con lista de URLs (una por línea).
  --audit-local             Auditar instalación local de PHP y php.ini en servidor/contenedor.
  --ini PATH                Ruta a archivo php.ini específico para auditoría local.
  -t, --threads NUM         Número de hilos concurrentes (default: 5).
  --timeout SEC             Timeout en segundos para cada petición (default: 8).
  --user-agent STR          User-Agent personalizado.
  -k, --insecure            Ignorar advertencias de certificados SSL autofirmados.
  --proxy PROXY_URL         Enviar tráfico a través de proxy HTTP/HTTPS.
  --deep                    Sondeo no invasivo de rutas de diagnóstico (/info.php, etc.).
  --no-ssl-check            Desactivar inspección pasiva de certificados SSL/TLS.
  -oJ, --output-json ARCH   Generar reporte estructurado en formato JSON.
  -oC, --output-csv ARCH    Generar reporte tabular en formato CSV.
  -oH, --output-html ARCH   Generar Dashboard interactivo moderno en HTML.
  -oS, --output-sarif ARCH  Generar reporte estándar OASIS SARIF v2.1.0 para GitHub Security.
  --webhook URL             Despachar alerta estructurada a Webhook (Slack/Discord/Teams).
  -q, --quiet               Modo silencioso (ideal para pipelines CI/CD).
```

---

## 6. Integración en CI/CD (GitHub Actions)

El repositorio incluye un workflow automatizado en [.github/workflows/security-audit.yml](.github/workflows/security-audit.yml) que:
1. Valida automáticamente la precisión del motor de detección contra casos de prueba unitarios.
2. Permite auditorías programadas semanales o manuales (`workflow_dispatch`).
3. Sube los resultados a **GitHub Code Scanning** vía SARIF.
4. Publica el Dashboard HTML como un artefacto descargable en cada ejecución.

---

## 7. Licencia

Este proyecto está bajo la Licencia [MIT](LICENSE).
