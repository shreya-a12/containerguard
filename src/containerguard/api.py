"""FastAPI application exposing ContainerGuard scans and history."""

from __future__ import annotations

import os
import re
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

from containerguard.analysis import analyze_trivy_report, load_trivy_report
from containerguard.database import get_scan, list_scans, save_scan
from containerguard.errors import ContainerGuardError
from containerguard.policy import evaluate_policy, load_policy
from containerguard.reports import write_reports
from containerguard.scanner import scan_image

app = FastAPI(
    title="ContainerGuard API",
    description="Local-first container image vulnerability scanning and policy enforcement.",
    version="0.2.0",
)

_IMAGE_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@+-]{0,254}$")


class ScanRequest(BaseModel):
    """Request body for a new image scan."""

    image: str = Field(min_length=1, max_length=255, description="Docker image reference")

    @field_validator("image")
    @classmethod
    def validate_image(cls, value: str) -> str:
        value = value.strip()
        if not _IMAGE_REFERENCE.fullmatch(value) or value.startswith("-"):
            raise ValueError("Provide a valid image reference without whitespace or shell syntax.")
        return value


def _reports_dir() -> Path:
    return Path(os.environ.get("CONTAINERGUARD_REPORTS_DIR", "reports"))


@app.get("/health", tags=["system"])
def health() -> dict[str, str]:
    """Simple liveness endpoint."""
    return {"status": "ok", "service": "containerguard-api"}


@app.post("/scans", status_code=201, tags=["scans"])
def create_scan(request: ScanRequest) -> dict:
    """Run Trivy, evaluate the default policy, write reports, and persist results."""
    reports_dir = _reports_dir()
    try:
        raw_report_path = scan_image(request.image, reports_dir)
        summary = analyze_trivy_report(load_trivy_report(raw_report_path))
        policy_result = evaluate_policy(summary, load_policy())
        report_paths = write_reports(summary, policy_result, reports_dir, raw_report_path.stem)
        record = save_scan(
            request.image,
            summary,
            policy_result,
            str(report_paths["json"]),
        )
        return {**record, "summary": summary, "policy": policy_result}
    except ContainerGuardError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except OSError as exc:
        raise HTTPException(status_code=500, detail="Could not persist scan results.") from exc


@app.get("/scans", tags=["scans"])
def scan_history(limit: int = Query(default=20, ge=1, le=100)) -> dict:
    """Return recent scan summaries, newest first."""
    return {"items": list_scans(limit=limit), "count": len(list_scans(limit=limit))}


@app.get("/scans/{scan_id}", tags=["scans"])
def scan_detail(scan_id: int) -> dict:
    """Return a saved scan, including normalized findings and policy violations."""
    record = get_scan(scan_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return record
