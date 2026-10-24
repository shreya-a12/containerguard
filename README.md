# ContainerGuard

**Docker Image Security Scanner** — a free, local-first DevSecOps tool for scanning container images with Trivy, interpreting findings in Python, enforcing configurable security policies, and producing actionable reports.

> **Project status:** Phase 2 — Trivy scanning integration and vulnerability analysis. Image scanning and analysis of saved Trivy JSON reports are implemented. Policy enforcement, polished JSON/Markdown/HTML reports, report comparison, and CI enforcement remain future phases.

## Goals

- Scan local or registry-accessible container images with [Trivy](https://trivy.dev/).
- Normalize vulnerability identifiers, affected packages, severity, and fix availability.
- Enforce configurable policies before images move through CI/CD.
- Generate JSON, Markdown, and HTML reports.
- Demonstrate remediation with before-and-after scans.
- Run locally and in GitHub Actions without paid APIs or cloud hosting.

## Technology

- Python 3.11+
- Trivy CLI
- pytest
- GitHub Actions (planned)

## Project structure

```text
src/containerguard/   Application package, Trivy integration, and analysis
tests/                Automated tests
reports/              Local generated Trivy JSON reports (not committed)
pyproject.toml        Package configuration and CLI entry point
```

## Local setup

Create and activate a virtual environment.

**Windows PowerShell**
```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev]"
```

**macOS / Linux**
```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e ".[dev]"
```

Install Trivy separately and ensure the `trivy` executable is available on your PATH. Follow the official [Trivy installation guide](https://trivy.dev/latest/getting-started/installation/). Verify the installation with:

```powershell
trivy --version
```

ContainerGuard does not need to execute the image to scan it. Trivy may need network access to pull the image and update its vulnerability database.

## Verify

```powershell
pytest -q
containerguard --help
containerguard --version
containerguard scan --help
containerguard analyze --help
```

## Usage

Scan an image and save Trivy's raw JSON report in the `reports` directory:

```powershell
containerguard scan python:3.12-slim
```

Choose a different report directory:

```powershell
containerguard scan python:3.12-slim --output-dir reports
```

Analyze an existing Trivy JSON report without rescanning the image:

```powershell
containerguard analyze reports/python_3.12-slim.trivy.json
```

The CLI prints total vulnerabilities and counts for CRITICAL, HIGH, MEDIUM, LOW, and UNKNOWN severity. Each normalized finding includes its vulnerability ID, package, installed/fixed versions, severity, title, target, and primary URL.

The `compare` command is reserved for Phase 3 and currently reports that it is not implemented.

## Planned implementation

1. **Foundation:** packaging, CLI structure, error types, and initial tests.
2. **Scanner and analysis:** Trivy integration, JSON parser, normalized findings, and severity summaries.
3. **Policies and reports:** deterministic pass/fail rules, JSON/Markdown/HTML reports, and report comparison.
4. **Docker and CI/CD:** sample image and GitHub Actions security gate.
5. **Hardening and release:** integration tests, remediation walkthrough, security review, and final documentation.

## Security principles

- Never execute the image being scanned as part of vulnerability analysis.
- Pass subprocess arguments safely; do not build shell commands from untrusted input.
- Treat scanner output as untrusted data.
- Do not commit secrets, virtual environments, caches, or generated private reports.
- A clean Trivy report does not prove an image is free of every security defect.

## License

See [LICENSE](LICENSE).
