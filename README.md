# ContainerGuard

**Docker Image Security Scanner** — a free, local-first DevSecOps tool for scanning container images with Trivy, interpreting findings in Python, enforcing configurable security policies, and producing actionable reports.

> **Project status:** Phase 1 — foundation and CLI skeleton. Scan execution, vulnerability analysis, reporting, and CI enforcement are planned for subsequent phases and are not implemented yet.

## Goals

- Scan local or registry-accessible Docker images with [Trivy](https://trivy.dev/).
- Normalize vulnerability identifiers, affected packages, severity, and fix availability.
- Enforce configurable policies before images move through CI/CD.
- Generate JSON, Markdown, and HTML reports.
- Demonstrate remediation with before-and-after scans.
- Run locally and in GitHub Actions without paid APIs or cloud hosting.

## Technology

- Python 3.11+
- Docker
- Trivy
- pytest
- GitHub Actions

## Project structure

```text
src/containerguard/   Application package and CLI
tests/                Automated tests
reports/              Local generated reports
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

## Verify the foundation

```bash
pytest -q
containerguard --help
containerguard --version
containerguard scan --help
containerguard analyze --help
containerguard compare --help
```

The commands currently define the intended CLI interface. Scan and analysis operations deliberately report that they are not implemented yet; later phases will add those capabilities.

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
