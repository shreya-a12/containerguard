"""SQLite persistence for ContainerGuard scan history."""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Any

DEFAULT_DB_PATH = Path("data") / "containerguard.db"


def database_path() -> Path:
    """Resolve the database path, allowing isolated test/runtime locations."""
    return Path(os.environ.get("CONTAINERGUARD_DB", str(DEFAULT_DB_PATH)))


def connect() -> sqlite3.Connection:
    """Open a row-aware SQLite connection and ensure the schema exists."""
    path = database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            image TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            total_vulnerabilities INTEGER NOT NULL,
            severity_counts_json TEXT NOT NULL,
            policy_passed INTEGER NOT NULL,
            violation_count INTEGER NOT NULL,
            report_path TEXT NOT NULL,
            summary_json TEXT NOT NULL
        )
        """
    )
    connection.commit()
    return connection


def save_scan(
    image: str,
    summary: dict[str, Any],
    policy_result: dict[str, Any],
    report_path: str,
) -> dict[str, Any]:
    """Persist a completed scan and return its public record."""
    with connect() as connection:
        cursor = connection.execute(
            """
            INSERT INTO scans (
                image, total_vulnerabilities, severity_counts_json,
                policy_passed, violation_count, report_path, summary_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                image,
                int(summary["total_vulnerabilities"]),
                json.dumps(summary["severity_counts"]),
                int(bool(policy_result["passed"])),
                int(policy_result["violation_count"]),
                report_path,
                json.dumps({"summary": summary, "policy": policy_result}),
            ),
        )
        scan_id = cursor.lastrowid
        row = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return _public_record(row, include_details=False)


def list_scans(limit: int = 20) -> list[dict[str, Any]]:
    """Return the newest scan records first."""
    with connect() as connection:
        rows = connection.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [_public_record(row, include_details=False) for row in rows]


def get_scan(scan_id: int) -> dict[str, Any] | None:
    """Return a scan record with normalized findings and policy details."""
    with connect() as connection:
        row = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if row is None:
            return None
        return _public_record(row, include_details=True)


def _public_record(row: sqlite3.Row, include_details: bool) -> dict[str, Any]:
    record: dict[str, Any] = {
        "id": row["id"],
        "image": row["image"],
        "created_at": row["created_at"],
        "total_vulnerabilities": row["total_vulnerabilities"],
        "severity_counts": json.loads(row["severity_counts_json"]),
        "policy_passed": bool(row["policy_passed"]),
        "violation_count": row["violation_count"],
        "report_path": row["report_path"],
    }
    if include_details:
        details = json.loads(row["summary_json"])
        record["summary"] = details["summary"]
        record["policy"] = details["policy"]
    return record
