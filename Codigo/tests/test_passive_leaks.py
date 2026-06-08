"""
Suite TDD para core/analyzers.py -> clase PassiveLeakDetector

Vectores testeados:
  1. Nonce en _wpnonce de URL del historial de redirecciones (301/302)
  2. Nonce en _wpnonce de la URL final (sin redirección previa)
  3. Nonce en cabecera Referer de la respuesta
  4. Múltiples URLs en historial, solo algunas con nonce
  5. FetchResult completamente limpio (caso negativo)
  6. URL con parámetro sin formato de nonce (falso positivo)
"""

import pytest

from core.analyzers import PassiveFinding, PassiveLeakDetector
from core.http_engine import FetchResult

# FIXTURES - FetchResult simulados con distintos escenarios pasivos


@pytest.fixture
def fetch_result_clean():
    # FetchResult sin ningún nonce expuesto en URLs ni cabeceras.
    return FetchResult(
        url="https://victim.local/blog/",
        text="<html><body>Hello</body></html>",
        status=200,
        headers={"Content-Type": "text/html"},
        history=[],
        error=None,
    )


@pytest.fixture
def fetch_result_nonce_in_redirect():
    """
    Simula una cadena de redirección 301 donde la URL intermedia
    contenía un nonce en el parámetro _wpnonce.
    Equivalente a: wp_nonce_url() aplicado a una acción de eliminación.
    """
    return FetchResult(
        url="https://victim.local/wp-admin/",  # URL final (tras redirect)
        text="",
        status=200,
        headers={"Content-Type": "text/html"},
        history=[
            # URL que generó la redirección - contiene el nonce expuesto
            "https://victim.local/wp-admin/post.php?post=123&action=trash&_wpnonce=a1b2c3d4e5",
        ],
        error=None,
    )


@pytest.fixture
def fetch_result_nonce_in_final_url():
    """
    La URL final (sin redirección) contiene un nonce en parámetro GET.
    Esto ocurre cuando el administrador comparte o guarda en favoritos
    un enlace de acción directa generado por wp_nonce_url().
    """
    return FetchResult(
        url="https://victim.local/wp-admin/post.php?post=456&action=trash&_wpnonce=b2c3d4e5f6",
        text="",
        status=200,
        headers={"Content-Type": "text/html"},
        history=[],
        error=None,
    )


@pytest.fixture
def fetch_result_nonce_in_referer():
    """
    La cabecera Referer de la respuesta contiene una URL con nonce.
    Ocurre cuando el servidor la incluye en la respuesta o cuando
    se analiza el encabezado enviado en la petición anterior.
    """
    return FetchResult(
        url="https://victim.local/wp-admin/",
        text="",
        status=200,
        headers={
            "Content-Type": "text/html",
            "Referer": "https://victim.local/wp-admin/post.php?post=789&action=trash&_wpnonce=c3d4e5f6a7",
        },
        history=[],
        error=None,
    )


@pytest.fixture
def fetch_result_multiple_redirects():
    """
    Historial con múltiples redirecciones, solo una de las cuales tiene nonce.
    """
    return FetchResult(
        url="https://victim.local/wp-admin/",
        text="",
        status=200,
        headers={"Content-Type": "text/html"},
        history=[
            "https://victim.local/wp-login.php",  # Sin nonce
            "https://victim.local/wp-admin/post.php?post=1&action=trash&_wpnonce=d4e5f6a7b8",  # Con nonce
            "https://victim.local/wp-admin/edit.php",  # Sin nonce
        ],
        error=None,
    )


# BLOQUE 1 - Contrato del objeto PassiveFinding


class TestPassiveFindingContract:
    # PassiveFinding debe cumplir el Data Schema de fugas pasivas.

    def _get_one_finding(self, fetch_result) -> PassiveFinding:
        detector = PassiveLeakDetector()
        findings = detector.analyze(fetch_result)
        assert len(findings) >= 1, "Se esperaba al menos un hallazgo"
        return findings[0]

    def test_finding_has_found_attribute(self, fetch_result_nonce_in_redirect):
        f = self._get_one_finding(fetch_result_nonce_in_redirect)
        assert hasattr(f, "found")

    def test_finding_found_is_true(self, fetch_result_nonce_in_redirect):
        f = self._get_one_finding(fetch_result_nonce_in_redirect)
        assert f.found is True

    def test_finding_has_nonce_value(self, fetch_result_nonce_in_redirect):
        f = self._get_one_finding(fetch_result_nonce_in_redirect)
        assert hasattr(f, "nonce_value")
        assert len(f.nonce_value) == 10

    def test_finding_has_leak_type(self, fetch_result_nonce_in_redirect):
        f = self._get_one_finding(fetch_result_nonce_in_redirect)
        assert hasattr(f, "leak_type")
        assert f.leak_type in ("get_param", "referer_header")

    def test_finding_has_source_url(self, fetch_result_nonce_in_redirect):
        f = self._get_one_finding(fetch_result_nonce_in_redirect)
        assert hasattr(f, "source_url")
        assert isinstance(f.source_url, str)

    def test_finding_has_context(self, fetch_result_nonce_in_redirect):
        f = self._get_one_finding(fetch_result_nonce_in_redirect)
        assert hasattr(f, "context")
        assert isinstance(f.context, dict)

    def test_analyze_returns_list(self, fetch_result_clean):
        detector = PassiveLeakDetector()
        result = detector.analyze(fetch_result_clean)
        assert isinstance(result, list)


# BLOQUE 2 - test_detect_nonce_in_get_params


class TestDetectNonceInGetParams:
    # El detector debe identificar nonces expuestos en parámetros GET tanto en el historial de redirecciones como en la URL final.

    def test_detect_nonce_in_get_params_from_redirect_history(
        self, fetch_result_nonce_in_redirect
    ):
        # Nonce en _wpnonce de la URL del historial de redirección.
        detector = PassiveLeakDetector()
        findings = detector.analyze(fetch_result_nonce_in_redirect)
        assert len(findings) == 1

    def test_nonce_value_extracted_correctly_from_get_param(
        self, fetch_result_nonce_in_redirect
    ):
        # El valor del nonce extraído del parámetro GET es correcto.
        detector = PassiveLeakDetector()
        findings = detector.analyze(fetch_result_nonce_in_redirect)
        assert findings[0].nonce_value == "a1b2c3d4e5"

    def test_leak_type_is_get_param_for_redirect(self, fetch_result_nonce_in_redirect):
        # El tipo de fuga debe ser 'get_param' para URLs con nonce en query string.
        detector = PassiveLeakDetector()
        findings = detector.analyze(fetch_result_nonce_in_redirect)
        assert findings[0].leak_type == "get_param"

    def test_source_url_contains_the_redirect_url(self, fetch_result_nonce_in_redirect):
        # source_url debe ser la URL del historial que contenía el nonce.
        detector = PassiveLeakDetector()
        findings = detector.analyze(fetch_result_nonce_in_redirect)
        assert "_wpnonce=a1b2c3d4e5" in findings[0].source_url

    def test_context_contains_param_name(self, fetch_result_nonce_in_redirect):
        # El contexto debe indicar el nombre del parámetro GET detectado.
        detector = PassiveLeakDetector()
        findings = detector.analyze(fetch_result_nonce_in_redirect)
        assert findings[0].context.get("param_name") == "_wpnonce"

    def test_detect_nonce_in_final_url_without_redirect(
        self, fetch_result_nonce_in_final_url
    ):
        # También debe detectarse si el nonce está en la URL final (sin redirect).
        detector = PassiveLeakDetector()
        findings = detector.analyze(fetch_result_nonce_in_final_url)
        assert len(findings) == 1
        assert findings[0].nonce_value == "b2c3d4e5f6"

    def test_detects_only_nonce_bearing_url_in_multi_redirect(
        self, fetch_result_multiple_redirects
    ):
        # Con múltiples redirecciones, solo se reporta la URL que tiene nonce.
        detector = PassiveLeakDetector()
        findings = detector.analyze(fetch_result_multiple_redirects)
        assert len(findings) == 1
        assert findings[0].nonce_value == "d4e5f6a7b8"


# BLOQUE 3 - test_detect_referer_leak


class TestDetectRefererLeak:
    # El detector debe identificar nonces expuestos en la cabecera Referer.

    def test_detect_referer_leak(self, fetch_result_nonce_in_referer):
        # Nonce detectado en la cabecera HTTP Referer.
        detector = PassiveLeakDetector()
        findings = detector.analyze(fetch_result_nonce_in_referer)
        assert len(findings) == 1

    def test_referer_leak_type_is_referer_header(self, fetch_result_nonce_in_referer):
        # El tipo de fuga debe ser 'referer_header'.
        detector = PassiveLeakDetector()
        findings = detector.analyze(fetch_result_nonce_in_referer)
        assert findings[0].leak_type == "referer_header"

    def test_referer_nonce_value_extracted_correctly(
        self, fetch_result_nonce_in_referer
    ):
        # El valor del nonce extraído de la cabecera Referer es correcto.
        detector = PassiveLeakDetector()
        findings = detector.analyze(fetch_result_nonce_in_referer)
        assert findings[0].nonce_value == "c3d4e5f6a7"

    def test_referer_context_contains_header_name(self, fetch_result_nonce_in_referer):
        # El contexto debe identificar que la fuente es la cabecera Referer.
        detector = PassiveLeakDetector()
        findings = detector.analyze(fetch_result_nonce_in_referer)
        assert findings[0].context.get("header_name") == "Referer"


# BLOQUE 4 - Casos negativos (control de falsos positivos)


class TestFalsePositivePrevention:
    # El detector NO debe generar hallazgos cuando no hay nonces pasivos.

    def test_clean_fetch_result_returns_empty_list(self, fetch_result_clean):
        # FetchResult sin nonces en ningún canal -> lista vacía.
        detector = PassiveLeakDetector()
        findings = detector.analyze(fetch_result_clean)
        assert findings == []

    def test_url_without_wpnonce_param_not_flagged(self):
        # URL con otros parámetros GET pero sin _wpnonce -> no detectar.
        result = FetchResult(
            url="https://victim.local/wp-admin/post.php?post=123&action=trash",
            text="",
            status=200,
            headers={},
            history=[],
            error=None,
        )
        detector = PassiveLeakDetector()
        assert detector.analyze(result) == []

    def test_referer_without_nonce_not_flagged(self):
        # Referer presente pero sin _wpnonce -> no detectar.
        result = FetchResult(
            url="https://victim.local/page/",
            text="",
            status=200,
            headers={"Referer": "https://victim.local/other-page/"},
            history=[],
            error=None,
        )
        detector = PassiveLeakDetector()
        assert detector.analyze(result) == []

    def test_short_nonce_value_in_url_not_flagged(self):
        # _wpnonce con valor demasiado corto (no es nonce WP válido).
        result = FetchResult(
            url="https://victim.local/wp-admin/post.php?_wpnonce=abc",
            text="",
            status=200,
            headers={},
            history=[],
            error=None,
        )
        detector = PassiveLeakDetector()
        assert detector.analyze(result) == []

    def test_error_fetch_result_returns_empty_list(self):
        # FetchResult con error de red -> no intentar analizar, lista vacía.
        result = FetchResult(
            url="https://victim.local/",
            text="",
            status=0,
            headers={},
            history=[],
            error="Timeout tras 10s",
        )
        detector = PassiveLeakDetector()
        assert detector.analyze(result) == []
