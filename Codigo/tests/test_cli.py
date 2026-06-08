"""
Suite TDD para core/cli.py
"""

import sys

import pytest

from core.cli import LEGAL_BANNER, build_parser

# BLOQUE 1 - Argumento obligatorio --url


class TestUrlArgument:
    # --url es el único argumento requerido del escáner.

    def test_url_is_required(self):
        # Sin --url el parser debe lanzar SystemExit (código 2 = error de uso).
        parser = build_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args([])
        assert exc_info.value.code == 2

    def test_url_is_stored_correctly(self):
        # El valor de --url se almacena en args.url sin modificaciones.
        parser = build_parser()
        args = parser.parse_args(["--url", "https://victim.local"])
        assert args.url == "https://victim.local"

    def test_url_accepts_http_and_https(self):
        # El parser acepta tanto http:// como https:// (validación semántica no es su responsabilidad).
        parser = build_parser()
        args_https = parser.parse_args(["--url", "https://example.com"])
        args_http = parser.parse_args(["--url", "http://example.com"])
        assert args_https.url == "https://example.com"
        assert args_http.url == "http://example.com"


# BLOQUE 2 - Argumento --threads


class TestThreadsArgument:
    # --threads controla la concurrencia del motor asíncrono (semáforo asyncio).

    def test_threads_default_is_5(self):
        # Sin --threads, el valor por defecto debe ser exactamente 5.
        parser = build_parser()
        args = parser.parse_args(["--url", "https://example.com"])
        assert args.threads == 5

    def test_threads_accepts_custom_value(self):
        # --threads acepta cualquier entero positivo.
        parser = build_parser()
        args = parser.parse_args(["--url", "https://example.com", "--threads", "10"])
        assert args.threads == 10

    def test_threads_is_integer(self):
        # El tipo de args.threads debe ser int, no string.
        parser = build_parser()
        args = parser.parse_args(["--url", "https://example.com", "--threads", "3"])
        assert isinstance(args.threads, int)

    def test_threads_rejects_non_integer(self):
        # Un valor no entero (como 'abc') debe lanzar SystemExit.
        parser = build_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["--url", "https://example.com", "--threads", "abc"])
        assert exc_info.value.code == 2


# BLOQUE 3 - Flag --debug


class TestDebugFlag:
    # --debug habilita el dump de peticiones/respuestas HTTP para análisis forense.

    def test_debug_is_false_by_default(self):
        # Sin --debug, el modo de depuración debe estar desactivado.
        parser = build_parser()
        args = parser.parse_args(["--url", "https://example.com"])
        assert args.debug is False

    def test_debug_is_true_when_flag_present(self):
        # Con --debug, el atributo debe ser True.
        parser = build_parser()
        args = parser.parse_args(["--url", "https://example.com", "--debug"])
        assert args.debug is True

    def test_debug_is_boolean(self):
        # El tipo de args.debug debe ser bool.
        parser = build_parser()
        args = parser.parse_args(["--url", "https://example.com", "--debug"])
        assert isinstance(args.debug, bool)


# BLOQUE 4 - Argumento --format


class TestFormatArgument:
    # --format determina el destino del reporte generado por el escáner.

    def test_format_default_is_stdout(self):
        # Sin --format, el valor por defecto debe ser 'stdout'.
        parser = build_parser()
        args = parser.parse_args(["--url", "https://example.com"])
        assert args.format == "stdout"

    def test_format_accepts_json(self):
        # --format json debe almacenarse correctamente.
        parser = build_parser()
        args = parser.parse_args(["--url", "https://example.com", "--format", "json"])
        assert args.format == "json"

    def test_format_accepts_stdout(self):
        # --format stdout debe almacenarse correctamente.
        parser = build_parser()
        args = parser.parse_args(["--url", "https://example.com", "--format", "stdout"])
        assert args.format == "stdout"

    def test_format_rejects_invalid_value(self):
        # Un valor no permitido como 'xml' debe lanzar SystemExit.
        parser = build_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["--url", "https://example.com", "--format", "xml"])
        assert exc_info.value.code == 2


# BLOQUE 5 - Argumento --timeout


class TestTimeoutArgument:
    # --timeout establece el límite de segundos por petición HTTP.

    def test_timeout_default_is_10(self):
        # Sin --timeout, el valor por defecto debe ser 10 segundos.
        parser = build_parser()
        args = parser.parse_args(["--url", "https://example.com"])
        assert args.timeout == 10

    def test_timeout_accepts_custom_value(self):
        # --timeout acepta valores enteros positivos.
        parser = build_parser()
        args = parser.parse_args(["--url", "https://example.com", "--timeout", "30"])
        assert args.timeout == 30

    def test_timeout_is_integer(self):
        # El tipo de args.timeout debe ser int.
        parser = build_parser()
        args = parser.parse_args(["--url", "https://example.com", "--timeout", "15"])
        assert isinstance(args.timeout, int)


# BLOQUE 6 - Banner legal


class TestLegalBanner:
    # LEGAL_BANNER debe existir y contener las advertencias éticas requeridas por RNF6.

    def test_banner_is_a_string(self):
        # LEGAL_BANNER debe ser una cadena de texto no vacía.
        assert isinstance(LEGAL_BANNER, str)
        assert len(LEGAL_BANNER) > 0

    def test_banner_contains_disclaimer_keyword(self):
        # El banner debe contener alguna forma de 'descargo' o 'disclaimer'.
        banner_lower = LEGAL_BANNER.lower()
        assert (
            "autorizado" in banner_lower
            or "disclaimer" in banner_lower
            or "responsabilidad" in banner_lower
        )

    def test_banner_mentions_legal_use(self):
        # El banner debe mencionar explícitamente el uso legal o autorizado.
        banner_lower = LEGAL_BANNER.lower()
        assert (
            "legal" in banner_lower
            or "permiso" in banner_lower
            or "consentimiento" in banner_lower
        )
