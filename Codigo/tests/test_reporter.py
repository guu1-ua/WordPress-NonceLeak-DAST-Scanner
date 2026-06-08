"""
Suite TDD para core/report.py -> clase ScannerReport
"""

import json

import pytest

from core.analyzers import PassiveFinding
from core.parsers import NonceMatch
from core.report import ReportFinding, ScannerReport

# FIXTURES - Hallazgos simulados de cada módulo de detección


@pytest.fixture
def frontend_finding() -> NonceMatch:
    # Hallazgo simulado del FrontendParser (script_tag).
    return NonceMatch(
        nonce_value="a1b2c3d4e5",
        variable_name="nonce",
        location="script_tag",
        evidence='var wpSettings = {"nonce":"a1b2c3d4e5"};',
        severity="high",
    )


@pytest.fixture
def json_finding() -> tuple:
    # Hallazgo simulado del JSONParser - tupla (key_path, value).
    return ("data.config.nonce", "b2c3d4e5f6")


@pytest.fixture
def passive_finding() -> PassiveFinding:
    # Hallazgo simulado del PassiveLeakDetector (get_param).
    return PassiveFinding(
        found=True,
        nonce_value="c3d4e5f6a7",
        leak_type="get_param",
        source_url="https://victim.local/wp-admin/post.php?_wpnonce=c3d4e5f6a7",
        context={"param_name": "_wpnonce"},
    )


@pytest.fixture
def populated_report(frontend_finding, json_finding, passive_finding) -> ScannerReport:
    # Reporte completo con un hallazgo de cada tipo.
    report = ScannerReport(target_url="https://victim.local/")
    report.add_frontend_finding(
        url="https://victim.local/",
        nonce_match=frontend_finding,
    )
    report.add_json_finding(
        url="https://victim.local/wp-json/",
        key_path=json_finding[0],
        nonce_value=json_finding[1],
    )
    report.add_passive_finding(passive_finding)
    return report


@pytest.fixture
def empty_report() -> ScannerReport:
    # Reporte vacío - sin hallazgos.
    return ScannerReport(target_url="https://victim.local/")


# BLOQUE 1 - Construcción y contrato básico de ScannerReport


class TestScannerReportConstruction:

    def test_report_initializes_with_target_url(self, empty_report):
        assert empty_report.target_url == "https://victim.local/"

    def test_report_starts_with_zero_findings(self, empty_report):
        assert len(empty_report.findings) == 0

    def test_report_has_timestamp(self, empty_report):
        assert hasattr(empty_report, "timestamp")
        assert isinstance(empty_report.timestamp, str)
        assert len(empty_report.timestamp) > 0

    def test_report_has_scan_duration(self, empty_report):
        assert hasattr(empty_report, "scan_duration_seconds")

    def test_findings_is_a_list(self, empty_report):
        assert isinstance(empty_report.findings, list)


# BLOQUE 2 - Ingesta de hallazgos desde los tres módulos


class TestFindingIngestion:

    def test_add_frontend_finding_increases_count(self, empty_report, frontend_finding):
        empty_report.add_frontend_finding("https://victim.local/", frontend_finding)
        assert len(empty_report.findings) == 1

    def test_add_json_finding_increases_count(self, empty_report, json_finding):
        empty_report.add_json_finding(
            "https://victim.local/wp-json/", json_finding[0], json_finding[1]
        )
        assert len(empty_report.findings) == 1

    def test_add_passive_finding_increases_count(self, empty_report, passive_finding):
        empty_report.add_passive_finding(passive_finding)
        assert len(empty_report.findings) == 1

    def test_three_findings_count_correctly(self, populated_report):
        assert len(populated_report.findings) == 3

    def test_each_finding_is_report_finding_instance(self, populated_report):
        for f in populated_report.findings:
            assert isinstance(f, ReportFinding)


# BLOQUE 3 - Schema del objeto ReportFinding (campos obligatorios)


class TestReportFindingSchema:
    # Cada ReportFinding debe tener los seis campos del Data Schema de gemini.md.

    def _get_frontend(self, populated_report) -> ReportFinding:
        return next(f for f in populated_report.findings if f.leak_type == "frontend")

    def _get_rest(self, populated_report) -> ReportFinding:
        return next(f for f in populated_report.findings if f.leak_type == "rest_ajax")

    def _get_passive(self, populated_report) -> ReportFinding:
        return next(f for f in populated_report.findings if f.leak_type == "passive")

    def test_finding_has_url(self, populated_report):
        f = self._get_frontend(populated_report)
        assert hasattr(f, "url") and isinstance(f.url, str)

    def test_finding_has_leak_type(self, populated_report):
        f = self._get_frontend(populated_report)
        assert f.leak_type in ("frontend", "rest_ajax", "passive")

    def test_finding_has_severity(self, populated_report):
        f = self._get_frontend(populated_report)
        assert f.severity in ("critical", "high", "medium", "low")

    def test_finding_has_nonce_value_10_chars(self, populated_report):
        for f in populated_report.findings:
            assert len(f.nonce_value) == 10

    def test_finding_has_context_dict(self, populated_report):
        for f in populated_report.findings:
            assert isinstance(f.context, dict)

    def test_finding_has_evidence_string(self, populated_report):
        for f in populated_report.findings:
            assert isinstance(f.evidence, str)

    def test_frontend_leak_type_is_frontend(self, populated_report):
        f = self._get_frontend(populated_report)
        assert f.leak_type == "frontend"

    def test_json_finding_leak_type_is_rest_ajax(self, populated_report):
        f = self._get_rest(populated_report)
        assert f.leak_type == "rest_ajax"

    def test_passive_finding_leak_type_is_passive(self, populated_report):
        f = self._get_passive(populated_report)
        assert f.leak_type == "passive"


# BLOQUE 4 - Serialización JSON


class TestJSONSerialization:
    # to_dict() y to_json() deben producir el schema definido en gemini.md.

    def test_to_dict_returns_dict(self, populated_report):
        result = populated_report.to_dict()
        assert isinstance(result, dict)

    def test_to_dict_has_meta_key(self, populated_report):
        result = populated_report.to_dict()
        assert "meta" in result

    def test_to_dict_has_summary_key(self, populated_report):
        result = populated_report.to_dict()
        assert "summary" in result

    def test_to_dict_has_findings_key(self, populated_report):
        result = populated_report.to_dict()
        assert "findings" in result

    def test_meta_contains_target_url(self, populated_report):
        meta = populated_report.to_dict()["meta"]
        assert meta["target_url"] == "https://victim.local/"

    def test_meta_contains_total_findings(self, populated_report):
        meta = populated_report.to_dict()["meta"]
        assert meta["total_findings"] == 3

    def test_meta_contains_timestamp(self, populated_report):
        meta = populated_report.to_dict()["meta"]
        assert "timestamp" in meta

    def test_summary_has_by_severity(self, populated_report):
        summary = populated_report.to_dict()["summary"]
        assert "by_severity" in summary
        by_sev = summary["by_severity"]
        assert all(k in by_sev for k in ("critical", "high", "medium", "low"))

    def test_summary_has_by_type(self, populated_report):
        summary = populated_report.to_dict()["summary"]
        assert "by_type" in summary
        by_type = summary["by_type"]
        assert all(k in by_type for k in ("frontend", "rest_ajax", "passive"))

    def test_summary_counts_one_per_type(self, populated_report):
        by_type = populated_report.to_dict()["summary"]["by_type"]
        assert by_type["frontend"] == 1
        assert by_type["rest_ajax"] == 1
        assert by_type["passive"] == 1

    def test_findings_list_length_matches_total(self, populated_report):
        d = populated_report.to_dict()
        assert len(d["findings"]) == d["meta"]["total_findings"]

    def test_each_finding_dict_has_all_schema_keys(self, populated_report):
        required = {
            "url",
            "leak_type",
            "severity",
            "nonce_value",
            "context",
            "evidence",
        }
        for f in populated_report.to_dict()["findings"]:
            assert required.issubset(f.keys())

    def test_to_json_returns_valid_json_string(self, populated_report):
        json_str = populated_report.to_json()
        assert isinstance(json_str, str)
        parsed = json.loads(json_str)  # No debe lanzar excepción
        assert "findings" in parsed

    def test_empty_report_has_zero_total_findings(self, empty_report):
        meta = empty_report.to_dict()["meta"]
        assert meta["total_findings"] == 0

    def test_empty_report_findings_list_is_empty(self, empty_report):
        assert empty_report.to_dict()["findings"] == []


# BLOQUE 5 - Duración del escaneo


class TestScanDuration:

    def test_finalize_sets_scan_duration(self, empty_report):
        # finalize() debe calcular y fijar la duración del escaneo.
        empty_report.finalize()
        assert empty_report.scan_duration_seconds >= 0

    def test_scan_duration_is_numeric(self, empty_report):
        empty_report.finalize()
        assert isinstance(empty_report.scan_duration_seconds, float)
