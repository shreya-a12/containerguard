"""Generate shareable reports from normalized scan summaries."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from containerguard.errors import ReportError


def write_reports(
    summary: dict[str, Any],
    policy_result: dict[str, Any] | None,
    output_dir: str | Path,
    stem: str = "containerguard-report",
) -> dict[str, Path]:
    """Write JSON, Markdown, and HTML summaries and return their paths."""
    destination = Path(output_dir)
    safe_stem = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in stem).strip("._-") or "report"
    payload = {"summary": summary, "policy": policy_result}
    paths = {
        "json": destination / f"{safe_stem}.json",
        "markdown": destination / f"{safe_stem}.md",
        "html": destination / f"{safe_stem}.html",
    }
    try:
        destination.mkdir(parents=True, exist_ok=True)
        paths["json"].write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        paths["markdown"].write_text(_markdown(summary, policy_result), encoding="utf-8")
        paths["html"].write_text(_html(summary, policy_result), encoding="utf-8")
    except OSError as exc:
        raise ReportError(f"Could not write reports to '{destination}': {exc}") from exc
    return paths


def _markdown(summary: dict[str, Any], policy_result: dict[str, Any] | None) -> str:
    lines = [
        "# ContainerGuard Scan Report",
        "",
        f"- **Image:** {summary.get('artifact_name') or '(not specified)'}",
        f"- **Total vulnerabilities:** {summary.get('total_vulnerabilities', 0)}",
        "",
        "## Severity summary",
        "",
        "| Severity | Count |",
        "|---|---:|",
    ]
    for severity, count in summary.get("severity_counts", {}).items():
        lines.append(f"| {severity} | {count} |")
    if policy_result is not None:
        lines.extend(["", "## Policy result", "", f"**{'PASS' if policy_result['passed'] else 'FAIL'}**"])
        lines.append(f"- Violations: {policy_result['violation_count']}")
        for item in policy_result["violations"]:
            lines.append(f"- {item['severity']} — {item['vulnerability_id']} ({item['package']}): {', '.join(item['reasons'])}")
    lines.extend(["", "## Findings", ""])
    if not summary.get("findings"):
        lines.append("No vulnerabilities were reported.")
    else:
        lines.extend(["| Severity | ID | Package | Installed | Fixed |", "|---|---|---|---|---|"])
        for item in summary["findings"]:
            lines.append(
                f"| {item.get('severity', 'UNKNOWN')} | {item.get('vulnerability_id', '')} | "
                f"{item.get('package', '')} | {item.get('installed_version', '')} | {item.get('fixed_version', '')} |"
            )
    return "\n".join(lines) + "\n"


def _html(summary: dict[str, Any], policy_result: dict[str, Any] | None) -> str:
    title = html.escape(str(summary.get("artifact_name") or "Container image"))
    rows = "".join(
        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            *(html.escape(str(item.get(key, ""))) for key in
              ("severity", "vulnerability_id", "package", "installed_version", "fixed_version"))
        )
        for item in summary.get("findings", [])
    )
    counts = "".join(
        f"<li>{html.escape(str(severity))}: {int(count)}</li>"
        for severity, count in summary.get("severity_counts", {}).items()
    )
    policy = ""
    if policy_result is not None:
        status = "PASS" if policy_result["passed"] else "FAIL"
        policy = f"<h2>Policy: {status}</h2><p>Violations: {int(policy_result['violation_count'])}</p>"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>ContainerGuard Report — {title}</title>
<style>body{{font-family:system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#172033}}
table{{border-collapse:collapse;width:100%;font-size:.9rem}}th,td{{border:1px solid #ddd;padding:.55rem;text-align:left}}th{{background:#f3f5f8}}code{{overflow-wrap:anywhere}}</style>
</head><body><h1>ContainerGuard Scan Report</h1><p><strong>Image:</strong> {title}</p>
<p><strong>Total vulnerabilities:</strong> {int(summary.get('total_vulnerabilities', 0))}</p>
<h2>Severity summary</h2><ul>{counts}</ul>{policy}<h2>Findings</h2>
<table><thead><tr><th>Severity</th><th>ID</th><th>Package</th><th>Installed</th><th>Fixed</th></tr></thead>
<tbody>{rows}</tbody></table></body></html>"""


def compare_summaries(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Compare findings using vulnerability ID, package, and target as identity."""
    def identity(item: dict[str, Any]) -> tuple[str, str, str]:
        return (
            str(item.get("vulnerability_id", "UNKNOWN-ID")),
            str(item.get("package", "unknown")),
            str(item.get("target", "unknown")),
        )

    before_map = {identity(item): item for item in before.get("findings", [])}
    after_map = {identity(item): item for item in after.get("findings", [])}
    fixed = sorted(set(before_map) - set(after_map))
    new = sorted(set(after_map) - set(before_map))
    remaining = sorted(set(before_map) & set(after_map))
    return {
        "before_image": before.get("artifact_name", ""),
        "after_image": after.get("artifact_name", ""),
        "before_total": len(before_map),
        "after_total": len(after_map),
        "fixed_count": len(fixed),
        "new_count": len(new),
        "remaining_count": len(remaining),
        "fixed": [before_map[key] for key in fixed],
        "new": [after_map[key] for key in new],
        "remaining": [after_map[key] for key in remaining],
    }
