"""
Suite TDD para core/parsers.py -> clase FrontendParser

Vectores de inyección testeados:
  1. JSON inline   -> var wpApiSettings = {"nonce":"a1b2c3d4e5"};
  2. Objeto JS     -> var plugin = {nonce: "b2c3d4e5f6", ajax_url: "..."};
  3. wp_nonce_field -> <input type="hidden" name="_wpnonce" value="c3d4e5f6a7"/>
  4. Variable JS   -> var _wpnonce = "d4e5f6a7b8";
  5. X-WP-Nonce    -> nonce asignado a cabecera en JS
  6. Múltiples nonces en un mismo documento
  7. HTML limpio   -> no debe devolver ningún hallazgo (caso negativo)
  8. Falsos positivos -> tokens de longitud incorrecta o sin contexto WP
"""

import pytest

from core.parsers import FrontendParser, NonceMatch

# BLOQUE 1 - Contrato del objeto NonceMatch


class TestNonceMatchContract:
    # NonceMatch debe cumplir el Data Schema definido en gemini.md.

    def _get_one_match(self, html: str) -> NonceMatch:
        parser = FrontendParser()
        matches = parser.parse(html, url="https://target.local/")
        assert len(matches) >= 1, "Se esperaba al menos un hallazgo"
        return matches[0]

    def test_match_has_nonce_value(self):
        html = '<script>var s={"nonce":"a1b2c3d4e5"};</script>'
        m = self._get_one_match(html)
        assert hasattr(m, "nonce_value")

    def test_match_has_variable_name(self):
        html = '<script>var s={"nonce":"a1b2c3d4e5"};</script>'
        m = self._get_one_match(html)
        assert hasattr(m, "variable_name")

    def test_match_has_location(self):
        html = '<script>var s={"nonce":"a1b2c3d4e5"};</script>'
        m = self._get_one_match(html)
        assert hasattr(m, "location")

    def test_match_has_evidence(self):
        html = '<script>var s={"nonce":"a1b2c3d4e5"};</script>'
        m = self._get_one_match(html)
        assert hasattr(m, "evidence")

    def test_match_has_severity(self):
        html = '<script>var s={"nonce":"a1b2c3d4e5"};</script>'
        m = self._get_one_match(html)
        assert hasattr(m, "severity")

    def test_nonce_value_is_correct_length(self):
        # Los nonces de WordPress tienen exactamente 10 caracteres.
        html = '<script>var s={"nonce":"a1b2c3d4e5"};</script>'
        m = self._get_one_match(html)
        assert len(m.nonce_value) == 10


# BLOQUE 2 - Extracción desde etiquetas <script>


class TestScriptTagExtraction:
    # Parser debe localizar nonces en cualquier bloque <script> del DOM.

    def test_extract_nonce_from_script_json_inline(self):
        """
        Patrón principal: JSON inline inyectado por wp_localize_script().
        var wpApiSettings = {"nonce":"a1b2c3d4e5"};
        """
        html = """
        <html><body>
        <script>
            var wpApiSettings = {"nonce":"a1b2c3d4e5"};
        </script>
        </body></html>
        """
        parser = FrontendParser()
        matches = parser.parse(html, url="https://target.local/")
        assert len(matches) == 1
        assert matches[0].nonce_value == "a1b2c3d4e5"

    def test_extract_nonce_from_script_object_literal(self):
        """
        Variante de objeto JS con comillas simples y sin comillas en clave.
        var plugin = {nonce: 'b2c3d4e5f6', ajax_url: '/wp-admin/admin-ajax.php'};
        """
        html = """
        <html><body>
        <script>
            var plugin = {nonce: 'b2c3d4e5f6', ajax_url: '/wp-admin/admin-ajax.php'};
        </script>
        </body></html>
        """
        parser = FrontendParser()
        matches = parser.parse(html, url="https://target.local/")
        assert len(matches) == 1
        assert matches[0].nonce_value == "b2c3d4e5f6"

    def test_extract_wpnonce_variable_assignment(self):
        # Variable JS directa: var _wpnonce = "d4e5f6a7b8"; Patrón de wp_add_inline_script() mal usado.
        html = """
        <html><body>
        <script>
            var _wpnonce = "d4e5f6a7b8";
        </script>
        </body></html>
        """
        parser = FrontendParser()
        matches = parser.parse(html, url="https://target.local/")
        assert len(matches) == 1
        assert matches[0].nonce_value == "d4e5f6a7b8"

    def test_location_is_script_tag_for_script_extraction(self):
        # Los hallazgos en <script> deben tener location='script_tag'.
        html = '<script>var s={"nonce":"a1b2c3d4e5"};</script>'
        parser = FrontendParser()
        matches = parser.parse(html, url="https://target.local/")
        assert matches[0].location == "script_tag"

    def test_variable_name_detected_as_nonce(self):
        # El campo variable_name debe reflejar el identificador detectado.
        html = '<script>var s={"nonce":"a1b2c3d4e5"};</script>'
        parser = FrontendParser()
        matches = parser.parse(html, url="https://target.local/")
        assert "nonce" in matches[0].variable_name.lower()

    def test_evidence_contains_snippet(self):
        # El campo evidence debe contener el fragmento de código con el nonce.
        html = '<script>var wpApiSettings = {"nonce":"a1b2c3d4e5"};</script>'
        parser = FrontendParser()
        matches = parser.parse(html, url="https://target.local/")
        assert "a1b2c3d4e5" in matches[0].evidence

    def test_extract_xwpnonce_in_script(self):
        # Asignación de X-WP-Nonce a cabecera en JS: headers['X-WP-Nonce'] = 'e5f6a7b8c9';
        html = """
        <html><body>
        <script>
            fetch('/wp-json/wp/v2/posts', {
                headers: {'X-WP-Nonce': 'e5f6a7b8c9'}
            });
        </script>
        </body></html>
        """
        parser = FrontendParser()
        matches = parser.parse(html, url="https://target.local/")
        assert len(matches) == 1
        assert matches[0].nonce_value == "e5f6a7b8c9"

    def test_nonce_in_nested_object(self):
        # Nonce anidado en objeto con múltiples propiedades. Simula wp_localize_script() con config compleja de plugin.
        html = """
        <script>
        var myPlugin = {
            ajax_url: "/wp-admin/admin-ajax.php",
            nonce: "f6a7b8c9d0",
            action: "delete_user",
            version: "2.0"
        };
        </script>
        """
        parser = FrontendParser()
        matches = parser.parse(html, url="https://target.local/")
        assert len(matches) == 1
        assert matches[0].nonce_value == "f6a7b8c9d0"


# BLOQUE 3 - Extracción desde campos <input>


class TestFormFieldExtraction:
    # Parser debe localizar nonces en campos input[type=hidden] de formularios.

    def test_extract_wpnonce_from_hidden_input(self):
        # wp_nonce_field() genera: <input type="hidden" name="_wpnonce" value="..."/>
        html = """
        <html><body>
        <form method="POST" action="/wp-admin/admin-post.php">
            <input type="hidden" id="my_nonce" name="_wpnonce" value="c3d4e5f6a7"/>
            <input type="submit" value="Enviar"/>
        </form>
        </body></html>
        """
        parser = FrontendParser()
        matches = parser.parse(html, url="https://target.local/")
        assert len(matches) == 1
        assert matches[0].nonce_value == "c3d4e5f6a7"

    def test_location_is_form_field_for_input_extraction(self):
        # Los hallazgos en <input> deben tener location='form_field'.
        html = """
        <form>
            <input type="hidden" name="_wpnonce" value="c3d4e5f6a7"/>
        </form>
        """
        parser = FrontendParser()
        matches = parser.parse(html, url="https://target.local/")
        assert matches[0].location == "form_field"

    def test_variable_name_is_wpnonce_for_form_field(self):
        # El campo variable_name debe ser '_wpnonce' para inputs de formulario.
        html = '<form><input type="hidden" name="_wpnonce" value="c3d4e5f6a7"/></form>'
        parser = FrontendParser()
        matches = parser.parse(html, url="https://target.local/")
        assert matches[0].variable_name == "_wpnonce"


# BLOQUE 4 - Múltiples nonces


class TestMultipleNonces:
    # Una página puede exponer más de un nonce simultáneamente.

    def test_detects_two_nonces_in_same_script(self):
        # Dos objetos JS con nonce en el mismo bloque script.
        html = """
        <script>
            var plugin1 = {"nonce":"a1b2c3d4e5"};
            var plugin2 = {"nonce":"f6a7b8c9d0"};
        </script>
        """
        parser = FrontendParser()
        matches = parser.parse(html, url="https://target.local/")
        values = {m.nonce_value for m in matches}
        assert "a1b2c3d4e5" in values
        assert "f6a7b8c9d0" in values

    def test_detects_nonce_from_script_and_form(self):
        # Nonce en <script> y otro en <form> en la misma página.
        html = """
        <html><body>
        <script>var s = {"nonce":"a1b2c3d4e5"};</script>
        <form>
            <input type="hidden" name="_wpnonce" value="c3d4e5f6a7"/>
        </form>
        </body></html>
        """
        parser = FrontendParser()
        matches = parser.parse(html, url="https://target.local/")
        assert len(matches) == 2
        values = {m.nonce_value for m in matches}
        assert "a1b2c3d4e5" in values
        assert "c3d4e5f6a7" in values


# BLOQUE 5 - Falsos positivos


class TestFalsePositivePrevention:
    # El parser NO debe generar hallazgos en HTML sin nonces reales.

    def test_clean_html_returns_empty_list(self):
        # HTML sin ningún nonce -> lista vacía.
        html = "<html><body><h1>Hello World</h1><p>No nonces here.</p></body></html>"
        parser = FrontendParser()
        matches = parser.parse(html, url="https://target.local/")
        assert matches == []

    def test_short_token_not_matched(self):
        # Un valor de menos de 10 caracteres NO es un nonce WP válido.
        html = '<script>var s = {"nonce":"abc123"};</script>'
        parser = FrontendParser()
        matches = parser.parse(html, url="https://target.local/")
        assert matches == []

    def test_long_token_not_matched(self):
        # Un valor de más de 10 caracteres NO es un nonce WP válido.
        html = '<script>var s = {"nonce":"a1b2c3d4e5f6g7"};</script>'
        parser = FrontendParser()
        matches = parser.parse(html, url="https://target.local/")
        assert matches == []

    def test_unrelated_field_name_not_matched(self):
        # Un campo 'token' genérico sin contexto WP no debe detectarse.
        html = '<script>var s = {"token":"a1b2c3d4e5"};</script>'
        parser = FrontendParser()
        matches = parser.parse(html, url="https://target.local/")
        assert matches == []

    def test_input_without_wpnonce_name_not_matched(self):
        # Un input hidden sin name='_wpnonce' no es un nonce de WordPress.
        html = (
            '<form><input type="hidden" name="csrf_token" value="a1b2c3d4e5"/></form>'
        )
        parser = FrontendParser()
        matches = parser.parse(html, url="https://target.local/")
        assert matches == []
