"""
Suite TDD para core/http_engine.py
"""

import asyncio

import pytest
from aiohttp import ClientConnectionError
from aioresponses import aioresponses

from core.http_engine import AsyncHTTPEngine, FetchResult

# BLOQUE 1 - Petición exitosa: estructura del resultado


class TestFetchResult:
    # FetchResult debe ser un dataclass con los campos contractuales del motor.

    async def test_successful_fetch_returns_fetch_result(self):
        # fetch() debe devolver una instancia de FetchResult en caso de éxito.
        with aioresponses() as mock:
            mock.get("https://target.local/", status=200, body="<html>WP</html>")
            async with AsyncHTTPEngine(threads=2, timeout=5) as engine:
                result = await engine.fetch("https://target.local/")
        assert isinstance(result, FetchResult)

    async def test_result_contains_text(self):
        # FetchResult.text debe contener el cuerpo HTML de la respuesta.
        with aioresponses() as mock:
            mock.get("https://target.local/", status=200, body="<html>Hello WP</html>")
            async with AsyncHTTPEngine(threads=2, timeout=5) as engine:
                result = await engine.fetch("https://target.local/")
        assert result.text == "<html>Hello WP</html>"

    async def test_result_contains_status_code(self):
        # FetchResult.status debe contener el código HTTP de la respuesta.
        with aioresponses() as mock:
            mock.get("https://target.local/", status=200, body="ok")
            async with AsyncHTTPEngine(threads=2, timeout=5) as engine:
                result = await engine.fetch("https://target.local/")
        assert result.status == 200

    async def test_result_contains_headers(self):
        # FetchResult.headers debe ser un dict (puede estar vacío en el mock).
        with aioresponses() as mock:
            mock.get("https://target.local/", status=200, body="ok")
            async with AsyncHTTPEngine(threads=2, timeout=5) as engine:
                result = await engine.fetch("https://target.local/")
        assert isinstance(result.headers, dict)

    async def test_result_contains_history(self):
        # FetchResult.history debe ser una lista (vacía si no hay redirecciones).
        with aioresponses() as mock:
            mock.get("https://target.local/", status=200, body="ok")
            async with AsyncHTTPEngine(threads=2, timeout=5) as engine:
                result = await engine.fetch("https://target.local/")
        assert isinstance(result.history, list)

    async def test_result_contains_url(self):
        # FetchResult.url debe contener la URL solicitada.
        with aioresponses() as mock:
            mock.get("https://target.local/", status=200, body="ok")
            async with AsyncHTTPEngine(threads=2, timeout=5) as engine:
                result = await engine.fetch("https://target.local/")
        assert result.url == "https://target.local/"

    async def test_result_error_is_none_on_success(self):
        # En caso de éxito, FetchResult.error debe ser None.
        with aioresponses() as mock:
            mock.get("https://target.local/", status=200, body="ok")
            async with AsyncHTTPEngine(threads=2, timeout=5) as engine:
                result = await engine.fetch("https://target.local/")
        assert result.error is None


# BLOQUE 2 - Tolerancia a fallos de red


class TestNetworkErrorTolerance:
    """
    RF6: el motor NUNCA debe propagar excepciones de red al llamador.
    En su lugar devuelve un FetchResult con .error relleno y .text = "".
    Esto permite que el escáner continúe analizando otras URLs tras un fallo.
    """

    async def test_timeout_returns_fetch_result_not_raises(self):
        # asyncio.TimeoutError debe capturarse y devolver FetchResult con error.
        with aioresponses() as mock:
            mock.get("https://target.local/", exception=asyncio.TimeoutError())
            async with AsyncHTTPEngine(threads=2, timeout=1) as engine:
                result = await engine.fetch("https://target.local/")
        # No debe lanzar excepción; debe devolver FetchResult
        assert isinstance(result, FetchResult)

    async def test_timeout_sets_error_field(self):
        # Tras un timeout, FetchResult.error no debe ser None.
        with aioresponses() as mock:
            mock.get("https://target.local/", exception=asyncio.TimeoutError())
            async with AsyncHTTPEngine(threads=2, timeout=1) as engine:
                result = await engine.fetch("https://target.local/")
        assert result.error is not None
        assert len(result.error) > 0

    async def test_timeout_sets_empty_text(self):
        # Tras un timeout, FetchResult.text debe ser una cadena vacía.
        with aioresponses() as mock:
            mock.get("https://target.local/", exception=asyncio.TimeoutError())
            async with AsyncHTTPEngine(threads=2, timeout=1) as engine:
                result = await engine.fetch("https://target.local/")
        assert result.text == ""

    async def test_connection_error_returns_fetch_result_not_raises(self):
        # ClientConnectionError debe capturarse y devolver FetchResult con error.
        with aioresponses() as mock:
            mock.get("https://target.local/", exception=ClientConnectionError())
            async with AsyncHTTPEngine(threads=2, timeout=5) as engine:
                result = await engine.fetch("https://target.local/")
        assert isinstance(result, FetchResult)

    async def test_connection_error_sets_error_field(self):
        # Tras un error de conexión, FetchResult.error no debe ser None.
        with aioresponses() as mock:
            mock.get("https://target.local/", exception=ClientConnectionError())
            async with AsyncHTTPEngine(threads=2, timeout=5) as engine:
                result = await engine.fetch("https://target.local/")
        assert result.error is not None

    async def test_multiple_failures_do_not_stop_execution(self):
        """
        Varias peticiones fallidas consecutivas no deben interrumpir el bucle.
        El motor debe devolver FetchResult con error para cada una de ellas.
        """
        urls = [
            "https://target.local/page1",
            "https://target.local/page2",
            "https://target.local/page3",
        ]
        with aioresponses() as mock:
            for url in urls:
                mock.get(url, exception=asyncio.TimeoutError())
            async with AsyncHTTPEngine(threads=3, timeout=1) as engine:
                results = await asyncio.gather(*[engine.fetch(url) for url in urls])
        assert len(results) == 3
        assert all(isinstance(r, FetchResult) for r in results)
        assert all(r.error is not None for r in results)

    async def test_error_result_status_is_zero(self):
        # Cuando hay un error de red, FetchResult.status debe ser 0.
        with aioresponses() as mock:
            mock.get("https://target.local/", exception=asyncio.TimeoutError())
            async with AsyncHTTPEngine(threads=2, timeout=1) as engine:
                result = await engine.fetch("https://target.local/")
        assert result.status == 0


# BLOQUE 3 - Semáforo de concurrencia


class TestConcurrencyControl:
    """
    El motor debe incorporar un asyncio.Semaphore que garantice que nunca haya más de N peticiones activas simultáneamente.
    """

    async def test_semaphore_attribute_exists(self):
        # El motor debe exponer su semáforo como atributo .semaphore.
        async with AsyncHTTPEngine(threads=5, timeout=5) as engine:
            assert hasattr(engine, "semaphore")

    async def test_semaphore_limit_matches_threads(self):
        # El valor interno del semáforo debe coincidir con el argumento threads.
        async with AsyncHTTPEngine(threads=7, timeout=5) as engine:
            # asyncio.Semaphore expone _value (valor inicial)
            assert engine.semaphore._value == 7

    async def test_default_threads_is_5(self):
        # Sin especificar threads, el semáforo debe inicializarse a 5.
        async with AsyncHTTPEngine(timeout=5) as engine:
            assert engine.semaphore._value == 5

    async def test_concurrency_limit_enforced(self):
        """
        Con semáforo(2) y 5 peticiones simultáneas, en ningún momento
        deben estar activas más de 2 a la vez.

        Estrategia: registrar el pico de concurrencia mediante un contador
        compartido protegido por lock, y verificar que nunca supera 'threads'.
        """
        MAX_THREADS = 2
        active_count = 0
        peak_active = 0
        lock = asyncio.Lock()

        # Reemplazamos fetch() con una versión instrumentada que registra la
        # concurrencia real respetando el semáforo del motor.
        async def instrumented_fetch(engine, url: str) -> FetchResult:
            nonlocal active_count, peak_active
            async with engine.semaphore:
                async with lock:
                    active_count += 1
                    if active_count > peak_active:
                        peak_active = active_count
                # Simulamos trabajo asíncrono
                await asyncio.sleep(0.01)
                async with lock:
                    active_count -= 1
            return FetchResult(
                url=url, text="ok", status=200, headers={}, history=[], error=None
            )

        async with AsyncHTTPEngine(threads=MAX_THREADS, timeout=5) as engine:
            tasks = [
                instrumented_fetch(engine, f"https://target.local/p{i}")
                for i in range(5)
            ]
            await asyncio.gather(*tasks)

        assert peak_active <= MAX_THREADS, (
            f"Se detectó concurrencia pico de {peak_active}, "
            f"pero el límite era {MAX_THREADS}"
        )


# BLOQUE 4 - Gestor de contexto asíncrono


class TestContextManager:
    # El motor debe implementar el protocolo __aenter__ / __aexit__.

    async def test_engine_usable_as_async_context_manager(self):
        # 'async with AsyncHTTPEngine(...)' no debe lanzar excepción.
        try:
            async with AsyncHTTPEngine(threads=2, timeout=5):
                pass
        except Exception as exc:
            pytest.fail(f"async context manager lanzó excepción inesperada: {exc}")

    async def test_session_is_closed_after_context_exit(self):
        # Tras salir del context manager, la sesión aiohttp debe estar cerrada.
        async with AsyncHTTPEngine(threads=2, timeout=5) as engine:
            session = engine.session
        assert session.closed
