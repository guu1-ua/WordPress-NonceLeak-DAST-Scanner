"""
Módulo de generación de reportes estructurados del NonceLeak Scanner.
"""

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from core.analyzers import PassiveFinding
from core.parsers import NonceMatch

logger = logging.getLogger(__name__)


# DATA CONTRACT UNIFICADO
@dataclass
class ReportFinding:
    """
    Todos los hallazgos (independientemente de su módulo de origen) se
    convierten a este formato antes de ser incluidos en el reporte.
    """

    url: str
    leak_type: str  # "frontend" | "rest_ajax" | "passive"
    severity: str  # "critical" | "high" | "medium" | "low"
    nonce_value: str
    context: Dict = field(default_factory=dict)
    evidence: str = ""

    def to_dict(self) -> Dict:
        return {
            "url": self.url,
            "leak_type": self.leak_type,
            "severity": self.severity,
            "nonce_value": self.nonce_value,
            "context": self.context,
            "evidence": self.evidence,
        }


# REPORTE
class ScannerReport:
    """
    Agrega y serializa todos los hallazgos del escaneo en un único reporte.
    """

    def __init__(self, target_url: str) -> None:
        self.target_url = target_url
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.scan_duration_seconds = 0.0
        self.findings: List[ReportFinding] = []
        self._start_time = time.monotonic()

    # Ingesta de hallazgos

    def add_frontend_finding(self, url: str, nonce_match: NonceMatch) -> None:
        """
        Normaliza un hallazgo de FrontendParser (script_tag o form_field) y lo añade al reporte.
        """
        finding = ReportFinding(
            url=url,
            leak_type="frontend",
            severity=nonce_match.severity,
            nonce_value=nonce_match.nonce_value,
            context={
                "variable_name": nonce_match.variable_name,
                "location": nonce_match.location,
            },
            evidence=nonce_match.evidence,
        )
        self.findings.append(finding)
        logger.debug("[Report] frontend -> %s '%s'", url, nonce_match.nonce_value)

    def add_json_finding(
        self,
        url: str,
        key_path: str,
        nonce_value: str,
        severity: str = "high",
    ) -> None:
        """
        Normaliza un hallazgo de JSONParser y lo añade al reporte.
        """
        finding = ReportFinding(
            url=url,
            leak_type="rest_ajax",
            severity=severity,
            nonce_value=nonce_value,
            context={
                "key_path": key_path,
                "location": "json_payload",
            },
            evidence=f'"{key_path}": "{nonce_value}"',
        )
        self.findings.append(finding)
        logger.debug("[Report] rest_ajax -> %s '%s' at %s", url, nonce_value, key_path)

    def add_passive_finding(self, passive: PassiveFinding) -> None:
        """
        Normaliza un hallazgo de PassiveLeakDetector y lo añade al reporte.
        """
        # Los nonces en URLs públicas tienen severidad media
        # Los expuestos en Referer tienen severidad alta
        severity = "high" if passive.leak_type == "referer_header" else "medium"

        finding = ReportFinding(
            url=passive.source_url,
            leak_type="passive",
            severity=severity,
            nonce_value=passive.nonce_value,
            context=passive.context,
            evidence=passive.source_url,
        )
        self.findings.append(finding)
        logger.debug(
            "[Report] passive/%s -> %s '%s'",
            passive.leak_type,
            passive.source_url,
            passive.nonce_value,
        )

    # Finalización

    def finalize(self) -> None:
        # Calcula la duración total del escaneo. Llamar antes de serializar.
        self.scan_duration_seconds = round(time.monotonic() - self._start_time, 3)

    # Serialización

    def to_dict(self) -> Dict:
        # Convierte el reporte completo al schema JSON de gemini.md.
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        by_type = {"frontend": 0, "rest_ajax": 0, "passive": 0}

        for f in self.findings:
            if f.severity in by_severity:
                by_severity[f.severity] += 1
            if f.leak_type in by_type:
                by_type[f.leak_type] += 1

        return {
            "meta": {
                "target_url": self.target_url,
                "timestamp": self.timestamp,
                "scan_duration_seconds": self.scan_duration_seconds,
                "total_findings": len(self.findings),
            },
            "summary": {
                "by_severity": by_severity,
                "by_type": by_type,
            },
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_json(self, indent: int = 2) -> str:
        # Serializa el reporte a JSON formateado.
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)
