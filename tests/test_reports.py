import json

from containerguard.reports import compare_summaries, write_reports


def sample_summary(image, findings):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for finding in findings:
        counts[finding["severity"]] += 1
    return {"artifact_name": image, "total_vulnerabilities": len(findings),
            "severity_counts": counts, "findings": findings}


def finding(cve, package="openssl", severity="HIGH"):
    return {"vulnerability_id": cve, "package": package, "target": "os",
            "severity": severity, "installed_version": "1.0", "fixed_version": "1.1"}


def test_write_reports_creates_json_markdown_html(tmp_path):
    summary = sample_summary("demo:latest", [finding("CVE-1")])
    policy = {"passed": False, "violation_count": 1, "violations": []}
    paths = write_reports(summary, policy, tmp_path, "demo")
    assert set(paths) == {"json", "markdown", "html"}
    assert json.loads(paths["json"].read_text(encoding="utf-8"))["summary"]["artifact_name"] == "demo:latest"
    assert "Policy result" in paths["markdown"].read_text(encoding="utf-8")
    assert "CVE-1" in paths["html"].read_text(encoding="utf-8")


def test_compare_summaries_identifies_new_and_fixed():
    before = sample_summary("before", [finding("CVE-1"), finding("CVE-2")])
    after = sample_summary("after", [finding("CVE-2"), finding("CVE-3")])
    result = compare_summaries(before, after)
    assert result["fixed_count"] == 1
    assert result["new_count"] == 1
    assert result["remaining_count"] == 1
