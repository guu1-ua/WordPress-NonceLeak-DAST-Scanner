"""
Punto de entrada y orquestador del NonceLeak Scanner.
"""

import asyncio
import logging
import sys

# Forzar UTF-8 en stdout/stderr para soportar el banner Unicode en Windows
if sys.stdout.encoding and sys.stdout.encoding.upper() not in ("UTF-8", "UTF8"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr.encoding and sys.stderr.encoding.upper() not in ("UTF-8", "UTF8"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
from urllib.parse import urljoin

try:
    import colorama
    from colorama import Fore, Style

    colorama.init(autoreset=True)
except ImportError:

    class DummyColor:
        def __getattr__(self, name):
            return ""

    Fore = DummyColor()
    Style = DummyColor()

from core.analyzers import PassiveLeakDetector
from core.cli import LEGAL_BANNER, build_parser
from core.http_engine import AsyncHTTPEngine
from core.parsers import FrontendParser, JSONParser
from core.report import ScannerReport

# CONFIGURACIÓN DE LOGGING


def _configure_logging(debug: bool) -> None:
    """
    Activa el logging detallado cuando --debug está presente.
    En modo normal solo se muestran WARNING y superior.
    """
    level = logging.DEBUG if debug else logging.WARNING
    format_ = "[%(levelname)s] %(name)s: %(message)s"
    logging.basicConfig(level=level, format=format_, stream=sys.stderr)

    if debug:
        # Habilitar dump de headers de aiohttp
        logging.getLogger("aiohttp.client").setLevel(logging.DEBUG)
        logging.getLogger("core").setLevel(logging.DEBUG)


# MOTOR DE ESCANEO


async def run_scan(args) -> ScannerReport:
    """
    Ejecuta los tres módulos de detección contra el objetivo y
    acumula los hallazgos en un ScannerReport unificado.

    Args:
        args: Namespace de argparse con url, threads, timeout, debug.

    Returns:
        ScannerReport listo para serializar.
    """
    report = ScannerReport(target_url=args.url)
    frontend = FrontendParser()
    json_p = JSONParser()
    passive = PassiveLeakDetector()

    # Asegurar que la URL base termine en barra para respetar subdirectorios con urljoin
    base_url = args.url if args.url.endswith("/") else args.url + "/"

    # Endpoints a inspeccionar con JSONParser (REST API y AJAX)
    api_endpoints = [
        urljoin(base_url, "wp-json/"),
        urljoin(base_url, "wp-admin/admin-ajax.php"),
    ]

    async with AsyncHTTPEngine(
        threads=args.threads,
        timeout=args.timeout,
        debug=args.debug,
    ) as engine:

        # Página raíz - extracción de frontend DOM
        logging.info("[*] Analizando HTML raíz: %s", args.url)
        root_result = await engine.fetch(args.url)

        if not root_result.error:
            # Frontend: buscar nonces en <script> y <input> del HTML
            for match in frontend.parse(root_result.text, url=args.url):
                report.add_frontend_finding(url=args.url, nonce_match=match)

            # Pasivo: analizar cadena de redirecciones y Referer de la raíz
            for finding in passive.analyze(root_result):
                report.add_passive_finding(finding)

            # Pasivo adicional: analizar enlaces <a> en el DOM que contengan nonces expuestos en parámetros GET
            try:
                from bs4 import BeautifulSoup

                soup = BeautifulSoup(root_result.text, "lxml")
                for link in soup.find_all("a", href=True):
                    href = link.get("href")
                    full_href = urljoin(args.url, href)
                    passive_finding = passive._extract_nonce_from_url(full_href)
                    if passive_finding:
                        report.add_passive_finding(passive_finding)
            except Exception as e:
                logging.debug("[~] Error al buscar links para fugas pasivas: %s", e)
        else:
            logging.warning("[!] Error al obtener raíz: %s", root_result.error)

        # Endpoints REST/AJAX - búsqueda recursiva en JSON
        for endpoint in api_endpoints:
            logging.info("[*] Analizando endpoint: %s", endpoint)
            api_result = await engine.fetch(endpoint)

            if api_result.error:
                logging.warning("[!] Error en %s: %s", endpoint, api_result.error)
                continue

            # Intentar parsear como JSON
            try:
                import json as _json

                data = _json.loads(api_result.text)
                for key_path, nonce_value in json_p.search(data):
                    report.add_json_finding(
                        url=endpoint,
                        key_path=key_path,
                        nonce_value=nonce_value,
                    )
            except (_json.JSONDecodeError, ValueError, TypeError):
                # El endpoint no devolvió JSON válido - no es un error
                logging.debug("[~] %s no devolvio JSON valido", endpoint)

            # Pasivo: analizar también las cadenas de redirección de los endpoints
            for finding in passive.analyze(api_result):
                report.add_passive_finding(finding)

    report.finalize()
    return report


# SALIDA DEL REPORTE


def _emit_report(report: ScannerReport, fmt: str) -> None:
    """
    Emite el reporte en el formato solicitado.

    Args:
        report : ScannerReport finalizado.
        fmt    : 'stdout' -> imprime coloreado en consola | 'json' -> escribe report.json
    """
    if fmt == "json":
        output_path = "report.json"
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(report.to_json())
        print(f"\n[+] Reporte guardado en: {output_path}")
        print(f"    Total hallazgos: {len(report.findings)}")

    else:  # stdout
        d = report.to_dict()
        print("\n" + Fore.CYAN + "=" * 70)
        print(
            Fore.CYAN + Style.BRIGHT + "  NONCE LEAK SCANNER - RESULTADOS DEL ESCANEO"
        )
        print(Fore.CYAN + "=" * 70)
        print(f"  Objetivo : {Style.BRIGHT}{d['meta']['target_url']}")
        print(f"  Duración : {d['meta']['scan_duration_seconds']}s")
        total_findings = d["meta"]["total_findings"]
        total_color = Fore.GREEN if total_findings == 0 else (Fore.RED + Style.BRIGHT)
        print(f"  Hallazgos: {total_color}{total_findings}")
        print()

        if not report.findings:
            print(
                f"  {Fore.GREEN + Style.BRIGHT}[OK] No se detectaron nonces expuestos."
            )
        else:
            by_type = d["summary"]["by_type"]
            print(f"  {Style.BRIGHT}Resumen por tipo:")
            for t, count in by_type.items():
                if count:
                    print(f"    · {t:<12} : {Fore.YELLOW + Style.BRIGHT}{count}")
            print()
            print(f"  {Style.BRIGHT}Hallazgos detallados:")
            print(Fore.CYAN + "  " + "-" * 66)
            for i, f in enumerate(d["findings"], 1):
                severity = f["severity"].lower()
                if severity == "critical":
                    sev_color = Fore.MAGENTA + Style.BRIGHT
                elif severity == "high":
                    sev_color = Fore.RED + Style.BRIGHT
                elif severity == "medium":
                    sev_color = Fore.YELLOW + Style.BRIGHT
                else:  # low
                    sev_color = Fore.BLUE + Style.BRIGHT

                sev_tag = f"[{f['severity'].upper()}]"
                print(
                    f"\n  {Fore.YELLOW}[{i}]{Fore.RESET} {sev_color}{sev_tag} {Fore.WHITE + Style.BRIGHT}{f['leak_type'].upper()}"
                )
                print(f"      URL       : {Fore.CYAN}{f['url']}")
                print(
                    f"      Nonce     : {Fore.GREEN + Style.BRIGHT}{f['nonce_value']}"
                )
                print(f"      Contexto  : {f['context']}")
                if f["evidence"]:
                    # Clean newlines from evidence snippet for neat console display
                    evidence_snippet = (
                        f["evidence"][:80].replace("\n", " ").replace("\r", "")
                    )
                    print(f"      Evidencia : {Style.DIM}{evidence_snippet}")

        print("\n" + Fore.CYAN + "=" * 70 + "\n")


# ENTRY POINT


def main() -> None:
    # Punto de entrada síncrono - parsea args, lanza el escaneo asíncrono.
    # 1. Banner legal
    print(LEGAL_BANNER)

    # 2. Parsear argumentos
    parser = build_parser()
    args = parser.parse_args()

    # 3. Configurar logging
    _configure_logging(args.debug)

    # 4. Confirmación de configuración
    print(f"[*] Objetivo  : {args.url}")
    print(f"[*] Threads   : {args.threads}")
    print(f"[*] Timeout   : {args.timeout}s")
    print(f"[*] Formato   : {args.format}")
    print(f"[*] Debug     : {'ACTIVADO' if args.debug else 'desactivado'}")
    print()

    # 5. Ejecutar escaneo asíncrono
    # Fix: Python 3.9 + aiohttp en Windows genera un RuntimeError cosmético al
    # cerrar el ProactorEventLoop. WindowsSelectorEventLoopPolicy lo evita.
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    try:
        report = asyncio.run(run_scan(args))
    except KeyboardInterrupt:
        print("\n[!] Escaneo interrumpido por el usuario.")
        sys.exit(0)

    # 6. Emitir reporte
    _emit_report(report, fmt=args.format)


if __name__ == "__main__":
    main()
