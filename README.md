# PHP2Shell Production URL Auditor

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0%20(stdlib%20only)-brightgreen.svg)]()
[![CVEs](https://img.shields.io/badge/CVE-2026--109618%20%7C%20CVE--2026--109619-red.svg)]()

Herramienta de auditoría remota, segura y **no destructiva** diseñada para escanear y evaluar URLs en entornos de producción frente a las vulnerabilidades críticas del intérprete core de PHP conocidas colectivamente como **PHP2Shell**.

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

## 2. Enfoque Seguro en Producción (Zero-Downtime Audit)

> [!CAUTION]
> **Peligro en Producción:** Las PoC ofensivas de CVE-2026-109618 inducen condiciones reales de OOM (Out-Of-Memory) y carreras UAF que provocan fallos de segmentación inmediatos (Crash / 502 Bad Gateway) en los pools de trabajadores (PHP-FPM, Apache, FrankenPHP).

Este script opera bajo un **enfoque estrictamente no destructivo**:
1. **Fingerprinting Pasivo:** Inspecciona cabeceras HTTP (`X-Powered-By`, `Server`, `Set-Cookie`), firmas de frameworks y respuestas de error.
2. **Heurística de Presencia de PHP:** Detecta si la URL corre bajo PHP aun cuando `expose_php = Off` oculte el número de versión (marcando el objetivo como `[ALERTA: POTENCIALMENTE VULNERABLE]` para revisión interna).
3. **Sondas No Invasivas:** Consulta hashes inofensivos de PHP Easter Eggs y patrones benignos que no saturan memoria ni alteran el estado de los workers.

---

## 3. Instalación

### Prerrequisitos
- Python 3.8 o superior (`python3 --version`).
- **Cero dependencias externas:** Utiliza exclusivamente librerías estándar de Python (`urllib`, `ssl`, `json`, `csv`, `concurrent.futures`, `re`, `argparse`).

### Opción A: Clonar el repositorio (Recomendado)
```bash
git clone https://github.com/jorgbot/PHP2Shell.git
cd PHP2Shell
chmod +x audit_php2shell.py
```

### Opción B: Instalación local vía pip (Comando CLI global)
```bash
git clone https://github.com/jorgbot/PHP2Shell.git
cd PHP2Shell
pip install .
# Ahora puede ejecutarse directamente como:
php2shell-audit -u https://ejemplo.com
```

---

## 4. Uso del Script

### Auditar una sola URL
```bash
python3 audit_php2shell.py -u https://midominio.com
```

### Auditar una lista de URLs desde archivo
```bash
python3 audit_php2shell.py -f targets_example.txt -t 10
```

### Exportar resultados a JSON y CSV
```bash
python3 audit_php2shell.py -f targets_example.txt -oJ reporte.json -oC reporte.csv
```

### Opciones y Parámetros
```text
  -u, --url URL             URL individual a auditar.
  -f, --file FILE           Archivo con lista de URLs (una por línea).
  -t, --threads NUM         Número de hilos concurrentes (default: 5).
  --timeout SEC             Timeout en segundos para cada petición (default: 8).
  --user-agent STR          Cabecera User-Agent personalizada.
  -k, --insecure            Ignorar advertencias de certificados SSL autofirmados.
  --proxy PROXY_URL         Enviar tráfico a través de proxy (ej. http://127.0.0.1:8080).
  --deep                    Escanear adicionalmente rutas diagnósticas (/info.php, etc.).
  -oJ, --output-json ARCH   Generar reporte estructurado en formato JSON.
  -oC, --output-csv ARCH    Generar reporte tabular en formato CSV.
  -q, --quiet               Modo silencioso (ideal para pipelines CI/CD).
```

---

## 5. Interpretación de Estados

- **`[CRÍTICO: VULNERABLE]`**: Se confirmó una versión de PHP inferior a la versión parcheada o una versión EOL sin soporte. Requiere actualización inmediata.
- **`[ALERTA: POTENCIALMENTE VULNERABLE]`**: Se confirmó la presencia de PHP (por cookies de sesión, headers o DOM), pero la versión exacta está oculta por configuración (`expose_php = Off`). Requiere validar la versión directamente en el servidor o contenedor.
- **`[SEGURO: PARCHEADO]`**: Se identificó una versión de PHP igual o superior a la versión corregida.
- **`[NO DETECTADO PHP]`**: La URL responde con otra tecnología (Node.js, Go, Python, CDN estático, etc.).
- **`[ERROR / INACCESIBLE]`**: Fallo de red, timeout o DNS.

---

## 6. Remediación Inmediata

1. **Actualizar el runtime de PHP:**
   - Si usa paquetes de sistema operativo (Debian/Ubuntu `apt`, RHEL/AlmaLinux `dnf`), aplique las actualizaciones de seguridad de emergencia lanzadas en octubre 2026.
   - En entornos de contenedores (Docker/Kubernetes), reconstruya las imágenes base con las nuevas etiquetas de PHP parcheadas.
2. **Reiniciar procesos de PHP:**
   Actualizar los binarios en disco no es suficiente; debe reiniciar los servicios para liberar memoria residual:
   ```bash
   systemctl restart php8.3-fpm    # o la versión correspondiente
   systemctl restart apache2
   ```
3. **Hardening:**
   Asegúrese de mantener en `/etc/php/.../php.ini`:
   ```ini
   expose_php = Off
   display_errors = Off
   ```

---

## 7. Licencia

Este proyecto está bajo la Licencia [MIT](LICENSE).
