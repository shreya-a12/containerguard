from fastapi.testclient import TestClient

from containerguard import api
from containerguard.database import get_scan, list_scans, save_scan


def test_health_endpoint():
    client = TestClient(api.app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_scan_request_rejects_shell_syntax():
    client = TestClient(api.app)
    response = client.post("/scans", json={"image": "python:3.12;whoami"})
    assert response.status_code == 422


def test_history_and_detail_endpoints(monkeypatch, tmp_path):
    monkeypatch.setenv("CONTAINERGUARD_DB", str(tmp_path / "test.db"))
    summary = {
        "artifact_name": "python:3.12-slim",
        "total_vulnerabilities": 1,
        "severity_counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0},
        "findings": [
            {
                "vulnerability_id": "CVE-TEST",
                "package": "demo",
                "installed_version": "1.0",
                "fixed_version": "1.1",
                "severity": "HIGH",
                "title": "Test finding",
                "target": "os",
                "primary_url": "",
            }
        ],
    }
    policy = {
        "passed": False,
        "blocked_severities": ["CRITICAL", "HIGH"],
        "fail_on_unfixed": False,
        "violation_count": 1,
        "violations": [{"vulnerability_id": "CVE-TEST", "package": "demo", "severity": "HIGH", "reasons": ["severity HIGH"]}],
    }
    saved = save_scan("python:3.12-slim", summary, policy, "reports/test.json")
    client = TestClient(api.app)

    history = client.get("/scans")
    assert history.status_code == 200
    assert history.json()["count"] == 1
    assert history.json()["items"][0]["id"] == saved["id"]

    detail = client.get(f"/scans/{saved['id']}")
    assert detail.status_code == 200
    assert detail.json()["summary"]["findings"][0]["vulnerability_id"] == "CVE-TEST"
    assert detail.json()["policy"]["passed"] is False

    assert client.get("/scans/999").status_code == 404


def test_history_limit_validation(monkeypatch, tmp_path):
    monkeypatch.setenv("CONTAINERGUARD_DB", str(tmp_path / "test.db"))
    client = TestClient(api.app)
    assert client.get("/scans?limit=0").status_code == 422
