"""Tests for Trivy JSON parsing and severity summaries."""

import json

import pytest

from containerguard.analysis import analyze_trivy_report, load_trivy_report
from containerguard.errors import ReportError


@pytest.fixture
def trivy_report():
    return {
        "SchemaVersion": 2,
        "ArtifactName": "demo:latest",
        "ArtifactType": "container_image",
        "Results": [
            {
                "Target": "alpine:3.19 (alpine 3.19.1)",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2025-0001",
                        "PkgName": "libssl",
                        "InstalledVersion": "1.0",
                        "FixedVersion": "1.1",
                        "Severity": "HIGH",
                        "Title": "Example high severity issue",
                        "PrimaryURL": "https://example.com/CVE-2025-0001",
                    },
                    {
                        "VulnerabilityID": "CVE-2025-0002",
                        "PkgName": "zlib",
                        "Severity": "critical",
                    },
                ],
            },
            {"Target": "config", "Misconfigurations": []},
        ],
    }


def test_analyze_trivy_report_normalizes_findings_and_counts(trivy_report):
    summary = analyze_trivy_report(trivy_report)
    assert summary["artifact_name"] == "demo:latest"
    assert summary["total_vulnerabilities"] == 2
    assert summary["severity_counts"] == {
        "CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0
    }
    assert summary["findings"][0]["vulnerability_id"] == "CVE-2025-0001"
    assert summary["findings"][0]["fixed_version"] == "1.1"
    assert summary["findings"][1]["severity"] == "CRITICAL"


def test_unknown_severity_is_normalized(trivy_report):
    trivy_report["Results"][0]["Vulnerabilities"][0]["Severity"] = "unusual"
    summary = analyze_trivy_report(trivy_report)
    assert summary["severity_counts"]["UNKNOWN"] == 1


def test_load_trivy_report_reads_json(tmp_path, trivy_report):
    path = tmp_path / "report.json"
    path.write_text(json.dumps(trivy_report), encoding="utf-8")
    assert load_trivy_report(path)["ArtifactName"] == "demo:latest"


def test_load_trivy_report_rejects_invalid_json(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ReportError, match="not valid JSON"):
        load_trivy_report(path)


def test_load_trivy_report_rejects_wrong_structure(tmp_path):
    path = tmp_path / "wrong.json"
    path.write_text(json.dumps({"ArtifactName": "demo"}), encoding="utf-8")
    with pytest.raises(ReportError, match="Results array"):
        load_trivy_report(path)
