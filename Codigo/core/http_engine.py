"""
Motor de red asíncrono del NonceLeak Scanner.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import aiohttp

logger = logging.getLogger(__name__)


# DATA CONTRACT
@dataclass
class FetchResult:
    url: str  # URL efectiva final
    text: str  # Cuerpo de la respuesta como cadena UTF-8
    status: int  # Código HTTP
    headers: Dict[str, str]  # Cabeceras HTTP de la respuesta
    history: List[str]  # Lista de URLs intermedias recorridas por redirecciones
    error: Optional[str] = None  # Descripción del error de red


# MOTOR ASÍNCRONO
class AsyncHTTPEngine:
    """
    Motor HTTP asíncrono con control de concurrencia y tolerancia a fallos.

    Args:
        threads : Concurrencia máxima (tamaño del asyncio.Semaphore). Default 5.
        timeout : Segundos máximos por petición. Default 10.
        debug   : Si True, loguea detalles de cada petición/respuesta.
    """

    # Cabeceras que imitan un navegador real para evitar bloqueos triviales
    _DEFAULT_HEADERS: Dict[str, str] = {
        "User-Agent": (
            "Mozilla/5.0 (compatible; NonceLeak-Scanner/1.0; "
            "+https://www.google.com/)"
        ),
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        "Accept-Language": "es-ES,es;q=0.9,en;q=0.8",
    }

    def __init__(
        self,
        threads: int = 5,
        timeout: int = 10,
        debug: bool = False,
    ) -> None:
        self.threads = threads
        self.timeout = timeout
        self.debug = debug

        # Semáforo: limita a `threads` peticiones activas simultáneamente
        self.semaphore = asyncio.Semaphore(threads)

        # La sesión se crea en __aenter__ y se cierra en __aexit__
        self.session: Optional[aiohttp.ClientSession] = None

    # Protocolo de gestor de contexto asíncrono
    async def __aenter__(self) -> "AsyncHTTPEngine":
        # Abre la sesión aiohttp compartida para toda la vida del motor.
        timeout_cfg = aiohttp.ClientTimeout(total=self.timeout)
        self.session = aiohttp.ClientSession(
            headers=self._DEFAULT_HEADERS,
            timeout=timeout_cfg,
        )
        logger.debug(
            "[Engine] Sesión aiohttp abierta (threads=%d, timeout=%ds)",
            self.threads,
            self.timeout,
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        # Cierra la sesión aiohttp de forma limpia, liberando conexiones.
        if self.session and not self.session.closed:
            await self.session.close()
            logger.debug("[Engine] Sesión aiohttp cerrada.")
        # Retornar False (implícito) -> no suprimimos excepciones externas
        return False

    # Método principal

    async def fetch(self, url: str) -> FetchResult:
        """
        Realiza una petición GET a `url` de forma segura.

        Args:
            url: URL completa a solicitar.

        Returns:
            FetchResult con los datos de la respuesta, o con .error relleno
            y .text="" / .status=0 en caso de fallo de red.
        """
        if self.debug:
            logger.debug("[Engine] --> GET %s", url)

        async with self.semaphore:  # <- Throttle de concurrencia
            return await self._do_fetch(url)

    async def _do_fetch(self, url: str) -> FetchResult:
        """
        Lógica interna de fetch. Separada de fetch() para facilitar el testing
        del semáforo de forma independiente a la lógica de error handling.
        """
        try:
            async with self.session.get(url, allow_redirects=True) as response:
                text = await response.text(errors="replace")

                # Extraer historial de redirecciones como lista de strings
                history = [str(r.url) for r in response.history]

                # Convertir cabeceras a dict plano serializable
                headers = dict(response.headers)

                if self.debug:
                    logger.debug(
                        "[Engine] <-- %d %s (redirs: %d, len: %d bytes)",
                        response.status,
                        url,
                        len(history),
                        len(text),
                    )

                return FetchResult(
                    url=str(response.url),
                    text=text,
                    status=response.status,
                    headers=headers,
                    history=history,
                    error=None,
                )

        # Manejo de errores de red
        except asyncio.TimeoutError:
            msg = f"Timeout tras {self.timeout}s"
            logger.warning("[Engine] TIMEOUT %s - %s", url, msg)
            return self._error_result(url, msg)

        except aiohttp.ClientConnectionError as exc:
            msg = f"Error de conexión: {exc}"
            logger.warning("[Engine] CONN_ERR %s - %s", url, msg)
            return self._error_result(url, msg)

        except aiohttp.ClientResponseError as exc:
            msg = f"Error HTTP {exc.status}: {exc.message}"
            logger.warning("[Engine] HTTP_ERR %s - %s", url, msg)
            return self._error_result(url, msg)

        except Exception as exc:  # pylint: disable=broad-except
            # Red de seguridad: nunca propagamos excepciones inesperadas
            msg = f"Error inesperado: {type(exc).__name__}: {exc}"
            logger.error("[Engine] UNEXPECTED %s - %s", url, msg)
            return self._error_result(url, msg)

    # Utilidad privada

    @staticmethod
    def _error_result(url: str, error_msg: str) -> FetchResult:
        # Construye un FetchResult normalizado para casos de error de red.
        return FetchResult(
            url=url,
            text="",
            status=0,
            headers={},
            history=[],
            error=error_msg,
        )
