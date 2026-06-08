"""
Módulo de detección de fugas pasivas en infraestructura de red.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from core.http_engine import FetchResult

logger = logging.getLogger(__name__)

# Patrón de validación de nonce WP (10 caracteres alfanuméricos)
_WP_NONCE_RE = re.compile(r"^[a-zA-Z0-9]{10}$")

# Nombres de parámetro/cabecera que pueden contener nonces en rutas pasivas
_GET_NONCE_PARAMS = {"_wpnonce", "wpnonce", "nonce"}
_REFERER_HEADERS = {"Referer", "referer", "REFERER"}


# DATA CONTRACT
@dataclass
class PassiveFinding:
    found: bool
    nonce_value: str  # nonce en si
    leak_type: str  # 'get_param' | 'referer_header'
    source_url: str  # URL o cabecera donde se encontró el nonce
    context: Dict = field(default_factory=dict)  # contexto del hallazgo


# DETECTOR
class PassiveLeakDetector:

    def analyze(self, result: FetchResult) -> List[PassiveFinding]:
        """
        Args:
            result: FetchResult devuelto por AsyncHTTPEngine.fetch().

        Returns:
            Lista de PassiveFinding. Vacía si no se detectan fugas pasivas.
        """
        # Si hubo un error de red, no hay nada que analizar
        if result.error:
            return []

        findings: List[PassiveFinding] = []

        # Módulo 1: nonces en parámetros GET (historial + URL final)
        findings.extend(self._scan_get_params(result))

        # Módulo 2: nonces en cabecera Referer
        findings.extend(self._scan_referer_header(result))

        if findings:
            logger.info(
                "[PassiveLeakDetector] %s -> %d fuga(s) pasiva(s) detectada(s)",
                result.url,
                len(findings),
            )

        return findings

    # Módulo 1: Parámetros GET

    def _scan_get_params(self, result: FetchResult) -> List[PassiveFinding]:
        """
        Analiza todas las URLs de la cadena de respuesta en busca de nonces en parámetros GET:
          1. Cada URL del historial de redirecciones (FetchResult.history)
          2. La URL final (FetchResult.url)
        """
        found: List[PassiveFinding] = []

        # Construir la lista completa de URLs a inspeccionar
        urls_to_check: List[str] = list(result.history) + [result.url]

        for url in urls_to_check:
            finding = self._extract_nonce_from_url(url)
            if finding:
                found.append(finding)

        return found

    def _extract_nonce_from_url(self, url: str) -> Optional[PassiveFinding]:
        """
        Usa urllib.parse para descomponer la URL y buscar nonces en la
        query string. Devuelve PassiveFinding si encuentra uno, None si no.
        """
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=False)
        except Exception:
            return None

        for param_name in _GET_NONCE_PARAMS:
            values = params.get(param_name, [])
            for value in values:
                if _WP_NONCE_RE.match(value):
                    logger.debug(
                        "[PassiveLeakDetector] GET param -> %s=%s en %s",
                        param_name,
                        value,
                        url,
                    )
                    return PassiveFinding(
                        found=True,
                        nonce_value=value,
                        leak_type="get_param",
                        source_url=url,
                        context={
                            "param_name": param_name,
                            "full_url": url,
                        },
                    )
        return None

    # Módulo 2: Cabecera Referer

    def _scan_referer_header(self, result: FetchResult) -> List[PassiveFinding]:
        """
        Inspecciona las cabeceras HTTP de la respuesta buscando una cabecera
        Referer que contenga una URL con _wpnonce en su query string.

        El Referer puede aparecer:
          - Como cabecera de REQUEST que el servidor hace eco en la respuesta.
          - En respuestas de depuración o endpoints de diagnóstico mal configurados.
        """
        found: List[PassiveFinding] = []

        for header_name in _REFERER_HEADERS:
            referer_value = result.headers.get(header_name)
            if not referer_value:
                continue

            finding = self._extract_nonce_from_url(referer_value)
            if finding:
                # Sobreescribir el leak_type para distinguirlo del GET param directo
                finding.leak_type = "referer_header"
                finding.source_url = referer_value
                finding.context = {
                    "header_name": header_name,
                    "referer_url": referer_value,
                    "param_name": finding.context.get("param_name", "_wpnonce"),
                }
                logger.debug(
                    "[PassiveLeakDetector] Referer -> %s=%s", header_name, referer_value
                )
                found.append(finding)

        return found
