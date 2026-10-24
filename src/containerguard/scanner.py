"""Safe subprocess integration with the Trivy CLI."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from containerguard.errors import ScannerError


def _image_filename(image: str) -> str:
    """Convert an image reference to a filesystem-safe filename."""
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", image).strip("._-")
    return (slug[:100] or "image") + ".trivy.json"


def scan_image(image: str, output_dir: str | Path = "reports", timeout: int = 900) -> Path:
    """Scan an image with Trivy and save its raw JSON report.

    Trivy receives an argument list (never a shell command) so image references
    cannot be interpreted as shell syntax.
    """
    if not image or not image.strip():
        raise ScannerError("An image reference is required.")

    executable = shutil.which("trivy")
    if executable is None:
        raise ScannerError(
            "Trivy was not found on PATH. Install Trivy first, then open a new terminal "
            "and verify with 'trivy --version'."
        )

    try:
        completed = subprocess.run(
            [executable, "image", "--format", "json", image],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise ScannerError(f"Trivy scan timed out after {timeout} seconds for '{image}'.") from exc
    except OSError as exc:
        raise ScannerError(f"Could not start Trivy: {exc}") from exc

    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        if len(detail) > 1200:
            detail = detail[-1200:]
        message = f"Trivy failed to scan '{image}' (exit code {completed.returncode})."
        if detail:
            message += f"\n{detail}"
        raise ScannerError(message)

    if not completed.stdout.strip():
        raise ScannerError("Trivy returned an empty report.")

    destination_dir = Path(output_dir)
    destination = destination_dir / _image_filename(image)
    try:
        destination_dir.mkdir(parents=True, exist_ok=True)
        destination.write_text(completed.stdout, encoding="utf-8")
    except OSError as exc:
        raise ScannerError(f"Could not save Trivy report to '{destination}': {exc}") from exc

    return destination
