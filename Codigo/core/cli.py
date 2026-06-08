"""
Interfaz de Línea de Comandos del NonceLeak Scanner.
"""

import argparse

# BANNER LEGAL
LEGAL_BANNER = """
╔══════════════════════════════════════════════════════════════════════════════╗
║        NonceLeak Scanner - Aviso Legal y Descargo de Responsabilidad         ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  Esta herramienta ha sido desarrollada EXCLUSIVAMENTE con fines académicos   ║
║  y de investigación en ciberseguridad (TFG - Grado en Ingeniería             ║
║  Informática).                                                               ║
║                                                                              ║
║  CONDICIONES DE USO LEGAL:                                                   ║
║    - Solo está AUTORIZADO su uso sobre sistemas de tu propiedad o sobre      ║
║      los que dispongas de consentimiento EXPRESO Y ESCRITO del propietario.  ║
║    - El uso de este escáner sobre sistemas sin permiso constituye un         ║
║      delito tipificado en el Artículo 197 bis del Código Penal español       ║
║      y en normativas equivalentes de otras jurisdicciones.                   ║
║                                                                              ║
║  DESCARGO DE RESPONSABILIDAD:                                                ║
║    El autor declina toda responsabilidad por el uso indebido, ilegal         ║
║    o malicioso de esta herramienta. El usuario asume en su totalidad         ║
║    las consecuencias legales derivadas de su uso.                            ║
║                                                                              ║
║  Al continuar, confirmas haber leído y aceptado estas condiciones.           ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""


# PARSER
def build_parser() -> argparse.ArgumentParser:
    """
    Construye y devuelve el parser de argumentos CLI del escáner.

    Separar la construcción del parser de la función main() permite
    testear la lógica de argumentos de forma unitaria sin efectos
    secundarios (sin imprimir el banner, sin iniciar el escáner).

    Returns:
        argparse.ArgumentParser configurado con todos los argumentos.
    """
    parser = argparse.ArgumentParser(
        prog="nonce-scanner",
        description=(
            "Escáner DAST de Nonce Leaks en WordPress. "
            "Detecta exposiciones de nonces en frontend, REST/AJAX e infraestructuras pasivas."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Ejemplos de uso:\n"
            "  python scanner.py --url https://target.local\n"
            "  python scanner.py --url https://target.local --threads 10 --debug\n"
            "  python scanner.py --url https://target.local --format json --timeout 30\n"
        ),
    )

    # Argumento principal (obligatorio)
    parser.add_argument(
        "--url",
        required=True,
        metavar="URL",
        help="URL base del sitio WordPress objetivo (ej. https://target.local).",
    )

    # Control de concurrencia
    parser.add_argument(
        "--threads",
        type=int,
        default=5,
        metavar="N",
        help=(
            "Número máximo de peticiones concurrentes. "
            "Default: 5. Aumentar puede saturar el servidor objetivo."
        ),
    )

    # Timeout por petición
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        metavar="SEG",
        help="Segundos máximos de espera por petición HTTP. Default: 10.",
    )

    # Formato de salida del reporte
    parser.add_argument(
        "--format",
        choices=["stdout", "json"],
        default="stdout",
        metavar="FORMATO",
        help=(
            "Formato del reporte de salida. "
            "'stdout' imprime en consola con colores. "
            "'json' escribe un archivo report.json. "
            "Opciones: {stdout, json}. Default: stdout."
        ),
    )

    # Flag de depuración / trazabilidad
    parser.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help=(
            "Activa el modo depuración: imprime dump completo de cada "
            "petición y respuesta HTTP para análisis forense."
        ),
    )

    return parser


# ENTRY POINT
def main() -> None:
    """
    Punto de entrada principal de la CLI.

    Flujo:
      1. Mostrar banner legal.
      2. Parsear argumentos.
      3. Inicializar y lanzar el motor del escáner.
    """
    # Paso 1: Banner de aviso legal antes de cualquier operación
    print(LEGAL_BANNER)

    # Paso 2: Parsear argumentos
    parser = build_parser()
    args = parser.parse_args()

    # Paso 3: Confirmación de configuración activa
    print(f"[*] Objetivo  : {args.url}")
    print(f"[*] Threads   : {args.threads}")
    print(f"[*] Timeout   : {args.timeout}s")
    print(f"[*] Formato   : {args.format}")
    print(f"[*] Debug     : {'ACTIVADO' if args.debug else 'desactivado'}")
    print()


if __name__ == "__main__":
    main()
