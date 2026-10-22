# PHP2Shell Enterprise Reconnaissance & Audit Suite

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0%20(stdlib%20only)-brightgreen.svg)]()
[![CVEs](https://img.shields.io/badge/CVE-2026--109618%20%7C%20CVE--2026--109619-red.svg)]()
[![Methodology](https://img.shields.io/badge/Framework-OWASP%20%7C%20NIST%20SP%20800--115-orange.svg)]()

Suite de auditoría remota, segura y **no destructiva** diseñada para escanear y evaluar la exposición de flotas de producción a las vulnerabilidades críticas del core de PHP conocidas como **PHP2Shell** (**CVE-2026-109618** y **CVE-2026-109619**), incorporando fingerprinting de ecosistema, detección de SAPI, CMS, WAF, Sistema Operativo y auditoría de hardening.

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

## 2. Capacidades de Reconocimiento No Destructivo

El auditor sigue los estándares de exploración defensiva de **NIST SP 800-115**, **OWASP Web Security Testing Guide (WSTG)** y **OSSTMM**:

1. **Detección de SAPI y Arquitectura de Ejecución:**
   - Identifica si el entorno corre sobre **Apache `mod_php`** (máximo riesgo en PHP2Shell al estar embebido en el proceso HTTP), **Nginx + PHP-FPM**, **LiteSpeed (LSPHP)** o **FrankenPHP**.
2. **Detección de CMS y Frameworks:**
   - Reconocimiento pasivo de WordPress, Drupal, Joomla, Laravel, Symfony, Magento, PrestaShop y Moodle.
3. **Fingerprinting de Sistema Operativo y Distribución Linux:**
   - Identifica Ubuntu, Debian, CentOS, RHEL, Alpine o Windows Server para contextualizar si el sistema aplica parches retrocompatibles (*backports*).
4. **Detección de WAF y CDN:**
   - Identifica proxies y firewalls perimetrales (Cloudflare, AWS WAF/CloudFront, Akamai, Imperva, Fastly, Sucuri).
5. **Auditoría de Hardening y Fugas de Información:**
   - Comprueba la directiva `expose_php`, directiva `display_errors` y ausencia de cabeceras de seguridad clave (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`).
6. **Dashboard Interactivo en HTML:**
   - Generación de reportes ejecutivos modernos y visuales con estadísticas, tablas responsivas y filtrado de severidad sin dependencias externas.

---

## 3. Instalación

### Prerrequisitos
- Python 3.8 o superior (`python3 --version`).
- **Cero dependencias externas:** Utiliza exclusivamente librerías estándar de Python (`urllib`, `ssl`, `json`, `csv`, `concurrent.futures`, `re`, `argparse`, `html`).

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

### Auditar una URL individual
```bash
python3 audit_php2shell.py -u https://midominio.com
```

### Auditar una lista masiva de URLs y generar Dashboard HTML
```bash
python3 audit_php2shell.py -f targets_example.txt -t 10 -oH dashboard.html
```

### Exportar en todos los formatos (JSON, CSV y HTML)
```bash
python3 audit_php2shell.py -f targets_example.txt -oJ reporte.json -oC reporte.csv -oH dashboard.html
```

### Parámetros Disponibles
```text
  -u, --url URL             URL individual para auditar.
  -f, --file FILE           Archivo con lista de URLs (una por línea).
  -t, --threads NUM         Número de hilos concurrentes (default: 5).
  --timeout SEC             Timeout en segundos para cada petición (default: 8).
  --user-agent STR          User-Agent personalizado.
  -k, --insecure            Ignorar advertencias de certificados SSL autofirmados.
  --proxy PROXY_URL         Enviar tráfico a través de proxy HTTP/HTTPS.
  --deep                    Sondeo no invasivo de rutas de diagnóstico (/info.php, etc.).
  -oJ, --output-json ARCH   Generar reporte estructurado en formato JSON.
  -oC, --output-csv ARCH    Generar reporte tabular en formato CSV.
  -oH, --output-html ARCH   Generar Dashboard interactivo moderno en HTML.
  -q, --quiet               Modo silencioso (ideal para pipelines CI/CD).
```

---

## 5. Interpretación de Estados

- **`[CRÍTICO: VULNERABLE]`**: Versión de PHP confirmada menor al umbral seguro o perteneciente a ramas EOL sin parche upstream.
- **`[ALERTA: POTENCIALMENTE VULNERABLE]`**: Presencia confirmada de PHP (por CMS, cookies o DOM), pero la versión exacta está oculta por configuración (`expose_php = Off`). Requiere validación interna en el servidor.
- **`[SEGURO: PARCHEADO]`**: Versión identificada igual o superior a la versión oficial corregida.
- **`[NO DETECTADO PHP]`**: La URL responde con otra tecnología (Node.js, Go, Python, CDN estático, etc.).
- **`[ERROR / INACCESIBLE]`**: Fallo de red, timeout o DNS.

---

## 6. Licencia

Este proyecto está bajo la Licencia [MIT](LICENSE).
