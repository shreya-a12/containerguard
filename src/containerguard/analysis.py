
"""Parse Trivy JSON reports into stable vulnerability findings and summaries."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from containerguard.errors import ReportError

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


def load_trivy_report(path: str | Path) -> dict[str, Any]:
    """Load and validate a Trivy JSON report from disk."""
    report_path = Path(path)

    try:
        content = report_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ReportError(
            f"Cannot read report '{report_path}': {exc}"
        ) from exc

    try:
        report = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ReportError(
            f"Report '{report_path}' is not valid JSON "
            f"(line {exc.lineno}, column {exc.colno})."
        ) from exc

    if not isinstance(report, dict):
        raise ReportError(
            f"Report '{report_path}' is not a valid Trivy JSON report: "
            "expected a JSON object."
        )

    # Normal Trivy vulnerability reports contain a Results array.
    # Some metadata-only reports, such as certain minimal images,
    # may omit Results entirely. Accept that format only when it has
    # recognizable Trivy report metadata.
    if "Results" not in report:
        has_trivy_metadata = (
            isinstance(report.get("SchemaVersion"), int)
            and isinstance(report.get("ArtifactName"), str)
            and isinstance(report.get("ArtifactType"), str)
            and isinstance(report.get("Metadata"), dict)
            and isinstance(report.get("Trivy"), dict)
        )

        if not has_trivy_metadata:
            raise ReportError(
                f"Report '{report_path}' is not a valid Trivy JSON report: "
                "expected a top-level Results array."
            )

        report["Results"] = []

    elif not isinstance(report["Results"], list):
        raise ReportError(
            f"Report '{report_path}' is not a valid Trivy JSON report: "
            "Results must be an array."
        )

    return report


def analyze_trivy_report(report: dict[str, Any]) -> dict[str, Any]:
    """Normalize vulnerability fields and calculate severity totals."""
    if not isinstance(report, dict):
        raise ReportError("Invalid Trivy report: expected a JSON object.")

    results = report.get("Results")

    if not isinstance(results, list):
        raise ReportError(
            "Invalid Trivy report: expected a top-level Results array."
        )

    findings: list[dict[str, Any]] = []

    for result in results:
        if not isinstance(result, dict):
            continue

        target = result.get("Target") or "unknown"
        vulnerabilities = result.get("Vulnerabilities") or []

        if not isinstance(vulnerabilities, list):
            continue

        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                continue

            severity = str(
                vulnerability.get("Severity") or "UNKNOWN"
            ).upper()

            if severity not in SEVERITIES:
                severity = "UNKNOWN"

            findings.append(
                {
                    "vulnerability_id": (
                        vulnerability.get("VulnerabilityID") or "UNKNOWN-ID"
                    ),
                    "package": vulnerability.get("PkgName") or "unknown",
                    "installed_version": (
                        vulnerability.get("InstalledVersion") or ""
                    ),
                    "fixed_version": vulnerability.get("FixedVersion") or "",
                    "severity": severity,
                    "title": vulnerability.get("Title") or "",
                    "target": target,
                    "primary_url": vulnerability.get("PrimaryURL") or "",
                }
            )

    counts = Counter(item["severity"] for item in findings)

    return {
        "artifact_name": report.get("ArtifactName") or "",
        "artifact_type": report.get("ArtifactType") or "",
        "schema_version": report.get("SchemaVersion"),
        "total_vulnerabilities": len(findings),
        "severity_counts": {
            severity: counts.get(severity, 0)
            for severity in SEVERITIES
        },
        "findings": findings,
    }


def print_summary(summary: dict[str, Any]) -> None:
    """Print a compact, human-readable vulnerability summary."""
    print(f"Image: {summary.get('artifact_name') or '(not specified)'}")
    print(f"Total vulnerabilities: {summary['total_vulnerabilities']}")

    for severity in SEVERITIES:
        print(f"  {severity:<8} {summary['severity_counts'][severity]}")
