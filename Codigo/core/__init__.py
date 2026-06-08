"""
Módulos de lógica de negocio del escáner.

Contenido del paquete:
  cli.py           Configuración de la interfaz de línea de comandos y banners legales (RF1)
  http_engine.py   Motor HTTP concurrente y asíncrono (RF6, RF7)
  parsers.py       Extracción de nonces del frontend DOM (RF2) y búsqueda recursiva en JSON (RF3)
  analyzers.py     Detección de fugas pasivas en parámetros GET y cabeceras Referer (RF4)
  report.py        Generación, serialización y orquestación del reporte final (RF5)
"""
