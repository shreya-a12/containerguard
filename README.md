# ContainerGuard

**Docker Image Security Scanner** — a free, local-first DevSecOps tool for scanning container images with Trivy, interpreting findings in Python, enforcing configurable security policies, and producing actionable reports.

> **Project status:** Phase 3 — Trivy scanning, vulnerability analysis, configurable severity policy evaluation, JSON/Markdown/HTML reports, and before/after report comparison are implemented in the feature branch. Frontend, API, persistent scan history, and CI security-gate integration are planned for later phases.

## Technology

- Python 3.11+
- Trivy CLI
- PyYAML for safe YAML policy loading
- pytest
- GitHub Actions for automated tests

## Local setup

**Windows PowerShell**
```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

Install Trivy separately and ensure `trivy` is on PATH. See the [official Trivy installation guide](https://trivy.dev/latest/getting-started/installation/).

## Verify

```powershell
pytest -q
containerguard --help
```

## Usage

Scan an image, evaluate the default policy, and generate raw plus formatted reports:

```powershell
containerguard scan python:3.12-slim
```

The default policy fails on CRITICAL or HIGH findings. Exit codes are:
- `0`: policy passed
- `1`: scan completed but policy failed
- `2`: scan, input, policy, or report error

Use the included YAML policy:

```powershell
containerguard scan python:3.12-slim --policy policies/default.yml
```

Example policy:

```yaml
fail_on_severity:
  - CRITICAL
  - HIGH
fail_on_unfixed: false
```

Analyze an existing raw Trivy JSON report without rescanning:

```powershell
containerguard analyze reports/python_3.12-slim.trivy.json --policy policies/default.yml
```

Compare two raw Trivy JSON reports:

```powershell
containerguard compare reports/before.trivy.json reports/after.trivy.json
```

Scan/analyze commands write a raw Trivy JSON report (scan only) and normalized JSON, Markdown, and HTML reports. Compare writes `reports/comparison.json`. Report output can be redirected with `--output-dir`.

## Roadmap

1. **Foundation:** packaging, CLI, typed errors, tests — complete.
2. **Scanner and analysis:** Trivy integration, normalized findings, severity summaries — complete.
3. **Policies and reports:** policy evaluation, JSON/Markdown/HTML reports, comparison — implemented in this branch.
4. **API and storage:** FastAPI endpoints and SQLite scan history.
5. **Frontend:** React + Tailwind security dashboard using real API data.
6. **DevSecOps integration:** Dockerized app, CI security gate, integration tests, documentation.

## Security principles

- Never execute the image being scanned as part of vulnerability analysis.
- Pass subprocess arguments safely; do not build shell commands from untrusted input.
- Load YAML with safe parsing and validate policy keys/values.
- Treat scanner output as untrusted data.
- Do not commit secrets, virtual environments, caches, or generated reports.
- A clean Trivy report does not prove an image is free of every security defect.

## License

See [LICENSE](LICENSE).
