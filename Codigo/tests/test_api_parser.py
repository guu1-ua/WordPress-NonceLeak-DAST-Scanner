"""
Suite TDD para core/parsers.py -> clase JSONParser

Vectores testeados:
  1. Nonce en clave raíz              -> {"nonce": "a1b2c3d4e5"}
  2. Nonce en objeto anidado          -> {"data": {"nonce": "..."}}
  3. Nonce en profundidad arbitraria  -> {"a": {"b": {"c": {"nonce": "..."}}}}
  4. Nonce dentro de array de objetos -> {"routes": [{"nonce": "..."}]}
  5. Clave "wpnonce" sin guión bajo   -> {"wpnonce": "..."}
  6. Clave "restNonce"                -> {"restNonce": "..."}
  7. JSON limpio                      -> sin hallazgos (caso negativo)
  8. Clave con "nonce" pero valor formato incorrecto (falso positivo)
  9. Múltiples nonces en distintas ramas del árbol JSON
"""

import pytest

from core.parsers import JSONParser

# FIXTURES - Payloads JSON simulados de endpoints WordPress reales


@pytest.fixture
def wp_json_root_schema():
    """
    Simula la respuesta de /wp-json/ - el schema raíz de la API REST.
    Algunos plugins mal implementados inyectan nonces aquí.
    """
    return {
        "name": "Mi Sitio WordPress",
        "description": "Una tienda online",
        "url": "https://victim.local",
        "home": "https://victim.local",
        "gmt_offset": 0,
        "namespaces": ["wp/v2", "vc/v1", "wc/v3"],
        "authentication": {},
        "routes": {},
        # Fuga: un plugin inserta su nonce en el schema raíz
        "nonce": "a1b2c3d4e5",
    }


@pytest.fixture
def wp_ajax_response_nested():
    """
    Simula la respuesta JSON de admin-ajax.php con nonce en objeto anidado.
    Patrón típico de plugins que devuelven configuración al frontend.
    """
    return {
        "success": True,
        "data": {
            "plugin_version": "3.2.1",
            "config": {
                "nonce": "b2c3d4e5f6",
                "ajax_url": "/wp-admin/admin-ajax.php",
                "debug": False,
            },
        },
    }


@pytest.fixture
def wp_rest_response_deep():
    # JSON con nonce enterrado a 4 niveles de profundidad.
    return {
        "level1": {
            "level2": {
                "level3": {
                    "level4": {
                        "nonce": "c3d4e5f6a7",
                        "action": "delete_post",
                    }
                }
            }
        }
    }


@pytest.fixture
def wp_rest_response_with_array():
    # JSON con array de objetos, donde uno de los objetos contiene un nonce.
    return {
        "status": "ok",
        "plugins": [
            {"name": "plugin-a", "version": "1.0"},
            {"name": "plugin-b", "version": "2.0", "nonce": "d4e5f6a7b8"},
            {"name": "plugin-c", "version": "3.0"},
        ],
    }


@pytest.fixture
def wp_rest_multiple_nonces():
    # JSON con nonces en distintas ramas del árbol (múltiples fugas).
    return {
        "rest_nonce": "e5f6a7b8c9",
        "forms": {
            "delete_form": {
                "wpnonce": "f6a7b8c9d0",
            },
            "upload_form": {
                "nonce": "a7b8c9d0e1",
            },
        },
    }


@pytest.fixture
def json_clean():
    # JSON sin nonces - el parser debe devolver lista vacía.
    return {
        "name": "Mi Sitio",
        "version": "6.4",
        "api_version": 2,
        "routes": {
            "/wp/v2/posts": {"methods": ["GET", "POST"]},
        },
        "authentication": {"cookie": {}},
    }


# BLOQUE 1 - Contrato de la interfaz


class TestJSONParserContract:
    # JSONParser.search() debe devolver siempre una lista de tuplas (ruta, valor).

    def test_returns_list(self, json_clean):
        parser = JSONParser()
        result = parser.search(json_clean)
        assert isinstance(result, list)

    def test_returns_empty_list_for_clean_json(self, json_clean):
        parser = JSONParser()
        result = parser.search(json_clean)
        assert result == []

    def test_each_item_is_a_tuple(self, wp_json_root_schema):
        parser = JSONParser()
        results = parser.search(wp_json_root_schema)
        assert len(results) >= 1
        assert isinstance(results[0], tuple)

    def test_tuple_has_two_elements(self, wp_json_root_schema):
        parser = JSONParser()
        results = parser.search(wp_json_root_schema)
        assert len(results[0]) == 2

    def test_first_element_is_key_path_string(self, wp_json_root_schema):
        parser = JSONParser()
        results = parser.search(wp_json_root_schema)
        key_path, _ = results[0]
        assert isinstance(key_path, str)

    def test_second_element_is_nonce_value_string(self, wp_json_root_schema):
        parser = JSONParser()
        results = parser.search(wp_json_root_schema)
        _, value = results[0]
        assert isinstance(value, str)
        assert len(value) == 10


# BLOQUE 2 - Búsqueda recursiva


class TestJSONRecursiveSearch:
    # El motor debe iterar recursivamente todo el árbol JSON.

    def test_finds_nonce_at_root_level(self, wp_json_root_schema):
        # Nonce en la raíz del JSON -> debe encontrarse.
        parser = JSONParser()
        results = parser.search(wp_json_root_schema)
        values = [v for _, v in results]
        assert "a1b2c3d4e5" in values

    def test_finds_nonce_one_level_deep(self):
        # Nonce en objeto anidado a 1 nivel.
        data = {"response": {"nonce": "a1b2c3d4e5"}}
        parser = JSONParser()
        results = parser.search(data)
        assert len(results) == 1
        assert results[0][1] == "a1b2c3d4e5"

    def test_finds_nonce_in_nested_config(self, wp_ajax_response_nested):
        # Nonce en data.config.nonce (2 niveles).
        parser = JSONParser()
        results = parser.search(wp_ajax_response_nested)
        values = [v for _, v in results]
        assert "b2c3d4e5f6" in values

    def test_finds_nonce_at_deep_level(self, wp_rest_response_deep):
        # Nonce enterrado a 4 niveles de profundidad.
        parser = JSONParser()
        results = parser.search(wp_rest_response_deep)
        values = [v for _, v in results]
        assert "c3d4e5f6a7" in values

    def test_finds_nonce_inside_array_of_objects(self, wp_rest_response_with_array):
        # Nonce dentro de un objeto que forma parte de una lista.
        parser = JSONParser()
        results = parser.search(wp_rest_response_with_array)
        values = [v for _, v in results]
        assert "d4e5f6a7b8" in values

    def test_finds_multiple_nonces_in_different_branches(self, wp_rest_multiple_nonces):
        # Múltiples nonces en distintas ramas deben detectarse todos.
        parser = JSONParser()
        results = parser.search(wp_rest_multiple_nonces)
        values = {v for _, v in results}
        assert "e5f6a7b8c9" in values  # rest_nonce
        assert "f6a7b8c9d0" in values  # forms.delete_form.wpnonce
        assert "a7b8c9d0e1" in values  # forms.upload_form.nonce


# BLOQUE 3 - Variantes de nombre de clave


class TestKeyNameVariants:
    # El parser debe detectar distintas formas del nombre de clave de nonce.

    def test_detects_key_named_nonce(self):
        # Clave exacta 'nonce'.
        data = {"nonce": "a1b2c3d4e5"}
        results = JSONParser().search(data)
        assert len(results) == 1

    def test_detects_key_named_wpnonce(self):
        # Clave 'wpnonce' (sin guión bajo).
        data = {"wpnonce": "b2c3d4e5f6"}
        results = JSONParser().search(data)
        assert len(results) == 1

    def test_detects_key_named_rest_nonce(self):
        # Clave 'rest_nonce' (con prefijo).
        data = {"rest_nonce": "c3d4e5f6a7"}
        results = JSONParser().search(data)
        assert len(results) == 1

    def test_detects_key_named_restNonce_camelcase(self):
        # Clave 'restNonce' (camelCase - patrón habitual en JS moderno).
        data = {"restNonce": "d4e5f6a7b8"}
        results = JSONParser().search(data)
        assert len(results) == 1

    def test_detects_key_containing_nonce_substring(self):
        # Cualquier clave que contenga la subcadena 'nonce' debe disparar detección.
        data = {"updraftplus_nonce": "e5f6a7b8c9"}
        results = JSONParser().search(data)
        assert len(results) == 1


# BLOQUE 4 - Ruta de clave en el resultado


class TestKeyPathInResult:
    # La ruta devuelta debe reflejar la posición exacta en el árbol JSON.

    def test_root_key_path_is_key_name(self):
        # Nonce en raíz -> ruta es simplemente el nombre de la clave.
        data = {"nonce": "a1b2c3d4e5"}
        results = JSONParser().search(data)
        key_path, _ = results[0]
        assert key_path == "nonce"

    def test_nested_key_path_uses_dot_notation(self):
        # Nonce en data.config.nonce -> ruta en notación de puntos.
        data = {"data": {"config": {"nonce": "a1b2c3d4e5"}}}
        results = JSONParser().search(data)
        key_path, _ = results[0]
        assert key_path == "data.config.nonce"

    def test_array_path_includes_index(self):
        # Nonce en array -> ruta incluye el índice: 'plugins[1].nonce'.
        data = {"plugins": [{"name": "a"}, {"nonce": "a1b2c3d4e5"}]}
        results = JSONParser().search(data)
        key_path, _ = results[0]
        assert "plugins" in key_path
        assert "nonce" in key_path


# BLOQUE 5 - Control de falsos positivos


class TestFalsePositivePrevention:
    # El parser NO debe reportar hallazgos cuando el valor no es un nonce WP válido.

    def test_value_too_short_not_matched(self):
        # Valor de menos de 10 caracteres no es un nonce WP.
        data = {"nonce": "abc123"}
        results = JSONParser().search(data)
        assert results == []

    def test_value_too_long_not_matched(self):
        # Valor de más de 10 caracteres no es un nonce WP.
        data = {"nonce": "a1b2c3d4e5f6g7h8"}
        results = JSONParser().search(data)
        assert results == []

    def test_value_with_special_chars_not_matched(self):
        # Valor con caracteres no alfanuméricos no es un nonce WP válido.
        data = {"nonce": "a1b2c3-d4e"}
        results = JSONParser().search(data)
        assert results == []

    def test_non_string_value_not_matched(self):
        # Si el valor de 'nonce' es un entero o null, no debe reportarse.
        data = {"nonce": 12345, "other_nonce": None}
        results = JSONParser().search(data)
        assert results == []

    def test_clean_wp_json_schema_returns_empty(self, json_clean):
        # Schema /wp-json/ legítimo sin nonces -> lista vacía.
        results = JSONParser().search(json_clean)
        assert results == []
