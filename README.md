# NonceLeak DAST Scanner

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: GPL v2](https://img.shields.io/badge/License-GPL_v2-blue.svg)](https://gnu.org/licenses/gpl.html)

**NonceLeak DAST Scanner** es una herramienta de pruebas de seguridad dinámica (DAST) desarrollada en Python, diseñada específicamente para automatizar la detección de fugas lógicas de tokens de seguridad de un solo uso (**nonces**) en el ecosistema WordPress. 

Este proyecto ha sido desarrollado en el marco de un **Trabajo Fin de Grado (TFG) en Ingeniería Informática** para validar empíricamente la hipótesis de las limitaciones que presentan los escáneres de seguridad tradicionales (como WPScan o firewalls basados en firmas) ante fugas lógicas en tiempo de ejecución.

---

## Características Principales

El escáner implementa una heurística híbrida de doble factor (contexto + formato) para analizar y extraer nonces expuestos a través de tres vectores de fuga:

*   **Análisis del DOM (Frontend):** Inspección de scripts inline, asignación de variables JavaScript, cabeceras HTTP de peticiones integradas (`X-WP-Nonce`) y campos ocultos de formularios (`<input type="hidden" name="_wpnonce">`).
*   **Análisis de REST API y AJAX (JSON):** Recorrido recursivo y estructurado de payloads JSON buscando claves candidatas (que contengan la subcadena `nonce`) con valores que cumplan el patrón alfanumérico de 10 caracteres propio de WordPress.
*   **Detección de Fugas Pasivas (Red):** Inspección del historial de redirecciones HTTP y de la cabecera `Referer` buscando parámetros GET expuestos en URLs de tránsito.
*   **Motor Asíncrono de Alto Rendimiento:** Basado en `asyncio` y `aiohttp` para realizar peticiones concurrentes y optimizar el tiempo de ejecución.

---

## Estructura del Repositorio

*   `Codigo/`: Contiene el código fuente completo del escáner en Python.
    *   `main.py`: Punto de entrada de la herramienta y orquestador del escaneo.
    *   `core/`: Módulos de lógica interna (analizadores pasivos, parsers HTML/JSON y motor HTTP).
*   `Plugin Test/`: Contiene un plugin vulnerable por diseño (`nonce-leak-lab.php`) utilizado como laboratorio local para validar la precisión del escáner.

---

## Instalación y Requisitos

### Requisitos Previos
*   Python 3.9 o superior instalado en el sistema.
*   Entorno de pruebas local (como una instalación limpia de WordPress en Docker o XAMPP).

### Paso 1: Clonar el repositorio
```bash
git clone https://github.com/tu-usuario/WordPress-NonceLeak-DAST-Scanner.git
cd WordPress-NonceLeak-DAST-Scanner/Codigo
```

### Paso 2: Instalar dependencias
Se recomienda utilizar un entorno virtual:
```bash
# Crear entorno virtual
python -m venv venv
# Activar (Windows)
.\venv\Scripts\activate
# Activar (Linux/macOS)
source venv/bin/activate

# Instalar librerías
pip install -r requirements.txt
```

---

## Manual de Uso

La herramienta se ejecuta desde la consola a través de `main.py`.

### Comandos y Sintaxis Básica
Para lanzar un escaneo rápido sobre tu entorno WordPress local:
```bash
python main.py --url http://localhost/wordpress
```

### Argumentos y Opciones Disponibles
Puedes modificar el comportamiento del escáner utilizando las siguientes banderas:

| Argumento | Descripción | Valor por Defecto |
| :--- | :--- | :--- |
| `--url` | **(Requerido)** La dirección URL del WordPress objetivo a analizar. | N/A |
| `-t`, `--threads` | Número de peticiones concurrentes máximas permitidas. | `5` |
| `--timeout` | Límite de tiempo en segundos para esperar la respuesta del servidor. | `10` |
| `-f`, `--format` | Formato del informe de salida (`stdout` coloreado en consola o `json`). | `stdout` |
| `--debug` | Habilita el logging detallado y depuración del tráfico de red. | Desactivado |

#### Ejemplo de reporte en formato JSON
Si necesitas integrar el escáner en otras herramientas o flujos de trabajo, puedes exportar los hallazgos directamente a un archivo:
```bash
python main.py --url http://localhost/wordpress --format json
```
Esto generará un archivo `report.json` con toda la telemetría y evidencias del escaneo.

---

## Guía de Validación (Exposición Segura vs. Vulnerabilidad)

Un nonce expuesto públicamente no constituye una vulnerabilidad por sí mismo. El escáner realiza un hallazgo de token legítimo (Verdadero Positivo de exposición), pero el auditor debe validar si dicho token permite un bypass de seguridad (Vulnerabilidad) o si su comportamiento es inocuo (Exposición Segura). Sigue esta guía:

1.  **Identifica la Acción:** Busca en la evidencia qué parámetro `action` de WordPress está ligado al nonce detectado (ej. `action=rate_my_post`).
2.  **Intercepta la Petición:** En el navegador, abre la pestaña de Red (`F12`), ejecuta la acción y copia la petición AJAX como comando `cURL`.
3.  **Simula un Ataque Anónimo:** Elimina la cabecera `Cookie` (sesión activa) de la petición cURL y ejecútala.
4.  **Evalúa la Respuesta:**
    *   **Exposición Segura (Uso Inocuo):** El servidor responde con `403 Forbidden` o `401 Unauthorized` (denegando el acceso), o bien la acción se ejecuta (`200 OK`) pero solo expone o recupera datos que ya son públicos por diseño en la web (como cargar entradas públicas).
    *   **Vulnerabilidad Confirmada (Bypass de Autorización):** El servidor ejecuta con éxito una acción sensible (como borrar un recurso, crear usuarios o alterar configuraciones) devolviendo éxito (`200 OK` o `{"success":true}`) a pesar de no contar con sesión de usuario, demostrando la ausencia de validación de roles en el servidor.

*Nota sobre Falsos Positivos de detección:* Un falso positivo real en esta herramienta consiste únicamente en aquellas cadenas de 10 caracteres capturadas por la expresión regular que en realidad no representan un nonce de WordPress de ningún tipo (por ejemplo, fragmentos de hashes de caché/CSS, IDs de analítica o valores temporales de bases de datos que por coincidencia cumplen con la longitud y formato buscados).

---

## Futuras Mejoras para el Proyecto

Para siguientes fases del proyecto o desarrollos de la comunidad, se proponen las siguientes mejoras de arquitectura:

*   **Módulo de Escaneo Autenticado:** Actualmente el escáner opera exclusivamente como un visitante anónimo. La adición de un gestor de sesiones que admita cookies o credenciales (mediante login HTTP POST a `wp-login.php`) permitiría al escáner acceder al panel interno `/wp-admin/`. Esto multiplicaría la tasa de descubrimiento de nonces y posibilitaría detectar vulnerabilidades de escalada de privilegios horizontales y verticales.
*   **Evasión de Cortafuegos (WAF) y Captchas:** El tráfico automatizado del escáner puede ser bloqueado en entornos reales por Firewalls de Aplicaciones Web (como Cloudflare o plugins WAF internos como Wordfence). Se plantea la integración de rotación de User-Agents, retrasos aleatorios entre peticiones (*throttling*) y compatibilidad con proxies SOCKS5/IPs VPN dinámicas para evadir restricciones de velocidad.
*   **Módulo de Explotación Activa Automática:** Incorporar un motor que intente validar el exploit de forma automática, replicando las peticiones sin cookies para evaluar de manera autónoma si la respuesta del servidor representa un fallo real de control de accesos.

---

## Descargo de Responsabilidad (Aviso Legal)

Este software ha sido desarrollado **exclusivamente con fines académicos y de investigación en ciberseguridad**. El uso del escáner sobre sistemas externos sin la autorización explícita y por escrito de su propietario es ilegal y puede constituir un delito tipificado en los códigos penales de múltiples jurisdicciones. El autor no se hace responsable del uso indebido, malicioso o perjudicial de esta herramienta.
