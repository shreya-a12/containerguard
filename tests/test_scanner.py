"""Tests for Trivy invocation without requiring Trivy or Docker locally."""

import subprocess

import pytest

from containerguard.errors import ScannerError
from containerguard import scanner


def test_scan_image_saves_raw_json_report(monkeypatch, tmp_path):
    monkeypatch.setattr(scanner.shutil, "which", lambda _: "trivy.exe")
    monkeypatch.setattr(
        scanner.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args=args[0], returncode=0, stdout='{"Results":[]}', stderr=""
        ),
    )
    report = scanner.scan_image("python:3.12-slim", tmp_path)
    assert report.exists()
    assert report.name == "python_3.12-slim.trivy.json"
    assert report.read_text(encoding="utf-8") == '{"Results":[]}'


def test_scan_image_errors_when_trivy_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(scanner.shutil, "which", lambda _: None)
    with pytest.raises(ScannerError, match="Trivy was not found"):
        scanner.scan_image("python:3.12-slim", tmp_path)


def test_scan_image_reports_trivy_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(scanner.shutil, "which", lambda _: "trivy.exe")
    monkeypatch.setattr(
        scanner.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args=args[0], returncode=1, stdout="", stderr="image not found"
        ),
    )
    with pytest.raises(ScannerError, match="image not found"):
        scanner.scan_image("missing:image", tmp_path)
