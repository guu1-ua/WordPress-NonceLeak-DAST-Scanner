"""
Módulo de extracción de nonces del DOM y de payloads JSON de WordPress.
"""

import logging
import re
from dataclasses import dataclass
from typing import Any, List, Tuple

from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


# DATA CONTRACT
@dataclass
class NonceMatch:
    nonce_value: str  # Token de 10 caracteres extraído
    variable_name: str  # Nombre de la variable/campo donde se encontró
    location: str  # 'script_tag' | 'form_field'
    evidence: str  # Fragmento de código fuente donde se detectó
    severity: str = "high"  # Default: exponer un nonce en frontend es alto riesgo


# PATRONES DE DETECCIÓN

# Patrón principal: clave nonce en objeto JSON/JS (clave entre comillas o sin ellas)
# Captura: "nonce": "a1b2c3d4e5"  |  nonce: 'a1b2c3d4e5'  |  "nonce":"a1b2c3d4e5"
_PATTERN_NONCE_JSON = re.compile(
    r"""["\']?_?nonce["\']?\s*:\s*["\']([a-zA-Z0-9]{10})["\']""",
    re.IGNORECASE,
)

# Patrón secundario: asignación de variable JS directa
# Captura: var _wpnonce = "a1b2c3d4e5";  |  var nonce = 'a1b2c3d4e5';
_PATTERN_NONCE_VAR = re.compile(
    r"""var\s+_?(?:wp)?nonce\s*=\s*["\']([a-zA-Z0-9]{10})["\']""",
    re.IGNORECASE,
)

# Patrón terciario: X-WP-Nonce en cabecera JS (fetch API / jQuery.ajax)
# Captura: 'X-WP-Nonce': 'a1b2c3d4e5'  |  "X-WP-Nonce": "a1b2c3d4e5"
_PATTERN_XWPNONCE = re.compile(
    r"""["\']X-WP-Nonce["\']\s*:\s*["\']([a-zA-Z0-9]{10})["\']""",
    re.IGNORECASE,
)

# Todos los patrones de script con su nombre de variable asociado
_SCRIPT_PATTERNS = [
    (_PATTERN_NONCE_JSON, "nonce"),
    (_PATTERN_NONCE_VAR, "_wpnonce"),
    (_PATTERN_XWPNONCE, "X-WP-Nonce"),
]

# PARSER


class FrontendParser:
    """
    Analizador estático del DOM de una página WordPress.

    Detecta nonces expuestos públicamente en:
      - Bloques <script> (JSON inline, variables JS, cabeceras fetch)
      - Campos <input type="hidden" name="_wpnonce"> de formularios
    """

    def parse(self, html: str, url: str) -> List[NonceMatch]:
        """
        Analiza el HTML completo y devuelve todos los nonces encontrados.

        Args:
            html : Texto HTML completo de la respuesta (FetchResult.text).
            url  : URL de origen (para logging).

        Returns:
            Lista de NonceMatch, vacía si no se detecta ningún nonce.
        """
        soup = BeautifulSoup(html, "lxml")
        matches: List[NonceMatch] = []

        # Fase 1: Extraer nonces de bloques <script>
        matches.extend(self._scan_scripts(soup, url))

        # Fase 2: Extraer nonces de campos <input> ocultos
        matches.extend(self._scan_form_fields(soup, url))

        if matches:
            logger.info(
                "[FrontendParser] %s -> %d nonce(s) detectado(s)", url, len(matches)
            )

        return matches

    # Fase 1: Scripts

    def _scan_scripts(self, soup: BeautifulSoup, url: str) -> List[NonceMatch]:
        # Itera todos los <script> del DOM y aplica los patrones de detección.
        found: List[NonceMatch] = []
        seen_values: set = set()  # Evitar duplicados del mismo valor

        for script_tag in soup.find_all("script"):
            script_text = script_tag.string or script_tag.get_text()
            if not script_text:
                continue

            for pattern, var_name in _SCRIPT_PATTERNS:
                for match in pattern.finditer(script_text):
                    nonce_value = match.group(1)

                    # Deduplicar: mismo valor ya registrado en este documento
                    if nonce_value in seen_values:
                        continue
                    seen_values.add(nonce_value)

                    # Extraer fragmento de evidencia (línea completa del match)
                    evidence = self._extract_evidence(script_text, match.start())

                    logger.debug(
                        "[FrontendParser] script_tag -> %s='%s' en %s",
                        var_name,
                        nonce_value,
                        url,
                    )

                    found.append(
                        NonceMatch(
                            nonce_value=nonce_value,
                            variable_name=var_name,
                            location="script_tag",
                            evidence=evidence,
                            severity="high",
                        )
                    )

        return found

    # Fase 2: Campos de formulario

    def _scan_form_fields(self, soup: BeautifulSoup, url: str) -> List[NonceMatch]:
        # Busca <input type='hidden' name='_wpnonce'> generados por wp_nonce_field().
        found: List[NonceMatch] = []

        for inp in soup.find_all("input", {"type": "hidden", "name": "_wpnonce"}):
            value = inp.get("value", "")

            # Validar que el valor tiene exactamente 10 caracteres alfanuméricos
            if not re.fullmatch(r"[a-zA-Z0-9]{10}", value):
                continue

            evidence = str(inp)
            logger.debug(
                "[FrontendParser] form_field -> _wpnonce='%s' en %s", value, url
            )

            found.append(
                NonceMatch(
                    nonce_value=value,
                    variable_name="_wpnonce",
                    location="form_field",
                    evidence=evidence,
                    severity="high",
                )
            )

        return found

    # Utilidad

    @staticmethod
    def _extract_evidence(text: str, match_start: int, context_chars: int = 80) -> str:
        """
        Extrae hasta `context_chars` caracteres alrededor de la posición
        del match para usar como evidencia en el reporte.
        """
        start = max(0, match_start - 10)
        end = min(len(text), match_start + context_chars)
        return text[start:end].strip()


# JSON PARSER

# Regex que valida que un valor string sea un nonce WP válido (10 alfanuméricos)
_WP_NONCE_VALUE = re.compile(r"^[a-zA-Z0-9]{10}$")

# Substring que debe aparecer en el nombre de la clave para considerarla candidata
_NONCE_KEY_SUBSTRING = "nonce"


class JSONParser:
    """
    Escáner recursivo de nonces en payloads JSON de la API REST de WordPress.

    Recorre el árbol JSON completo (dicts, listas, valores anidados) buscando
    claves que contengan la subcadena 'nonce' y cuyos valores sean strings
    de exactamente 10 caracteres alfanuméricos (formato nonce de WordPress).
    """

    def search(self, data: Any) -> List[Tuple[str, str]]:
        """
        Punto de entrada público. Inicia la búsqueda recursiva desde la raíz.

        Args:
            data: Diccionario Python resultante de json.loads() o equivalente.

        Returns:
            Lista de tuplas (key_path, nonce_value). Vacía si no hay hallazgos.
        """
        results: List[Tuple[str, str]] = []
        self._recurse(data, path="", results=results)
        if results:
            logger.info(
                "[JSONParser] %d nonce(s) detectado(s) en el payload JSON", len(results)
            )
        return results

    # Motor recursivo

    def _recurse(
        self,
        node: Any,
        path: str,
        results: List[Tuple[str, str]],
    ) -> None:
        """
        Recorre recursivamente el nodo JSON en cualquier profundidad.
        """
        if isinstance(node, dict):
            for key, value in node.items():
                child_path = f"{path}.{key}" if path else key
                # ¿La clave contiene la subcadena 'nonce' (case-insensitive)?
                if _NONCE_KEY_SUBSTRING in key.lower():
                    self._check_leaf(child_path, value, results)
                else:
                    # Seguir bajando aunque la clave no sea candidata
                    self._recurse(value, child_path, results)

        elif isinstance(node, list):
            for index, item in enumerate(node):
                child_path = f"{path}[{index}]"
                self._recurse(item, child_path, results)

        # Los valores escalares no-string (int, bool, None) se omiten

    def _check_leaf(
        self,
        key_path: str,
        value: Any,
        results: List[Tuple[str, str]],
    ) -> None:
        """
        Valida si `value` es un nonce WP válido y lo registra.

        Si el valor es un dict o list (la clave 'nonce' contiene un objeto),
        continúa la recursión en lugar de registrar un hallazgo.
        """
        if isinstance(value, str):
            if _WP_NONCE_VALUE.match(value):
                logger.debug(
                    "[JSONParser] Nonce encontrado -> %s = '%s'", key_path, value
                )
                results.append((key_path, value))
            # else: string con formato incorrecto -> falso positivo descartado

        elif isinstance(value, (dict, list)):
            # La clave se llama 'nonce' pero contiene un objeto/array anidado
            # -> seguir buscando dentro por si hay nonces reales más profundos
            self._recurse(value, key_path, results)

        # int / bool / None -> omitidos
