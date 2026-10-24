# ContainerGuard

**Docker Image Security Scanner** — a free, local-first DevSecOps tool for scanning container images with Trivy, interpreting findings in Python, enforcing configurable security policies, and producing actionable reports.

> **Project status:** Phase 4 — Trivy scanning, vulnerability analysis, configurable policy evaluation, JSON/Markdown/HTML reports, comparison, a FastAPI service, and SQLite scan history are implemented in this feature branch. React dashboard and CI security-gate integration are planned next.

## Technology

- Python 3.11+
- Trivy CLI
- FastAPI + Uvicorn for the REST API
- SQLite for local scan history
- PyYAML for safe YAML policy loading
- pytest + HTTPX for automated tests
- GitHub Actions for continuous integration

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

## CLI usage

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

Scan/analyze commands write normalized JSON, Markdown, and HTML reports. Compare writes `reports/comparison.json`. Report output can be redirected with `--output-dir`.

## REST API

Start the local API from the repository root:

```powershell
uvicorn containerguard.api:app --reload
```

Open interactive API documentation at [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs).

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/health` | Check API liveness |
| POST | `/scans` | Scan an image, evaluate the default policy, write reports, and save history |
| GET | `/scans?limit=20` | List recent scan summaries (limit 1–100) |
| GET | `/scans/{id}` | Get scan details, findings, and policy violations |

Example request body for `POST /scans`:

```json
{
  "image": "python:3.12-slim"
}
```

The scan endpoint runs Trivy and therefore needs Trivy installed and network access to pull images/update its vulnerability database as needed. A completed scan that fails policy is still saved and returned; policy failure is distinct from an API error.

By default, SQLite history is stored at `data/containerguard.db`, and reports are written to `reports/`. Optional environment variables `CONTAINERGUARD_DB` and `CONTAINERGUARD_REPORTS_DIR` override these local paths.

## Roadmap

1. **Foundation:** packaging, CLI, typed errors, tests — complete.
2. **Scanner and analysis:** Trivy integration, normalized findings, severity summaries — complete.
3. **Policies and reports:** policy evaluation, JSON/Markdown/HTML reports, comparison — complete.
4. **API and storage:** FastAPI endpoints and SQLite scan history — implemented in this branch.
5. **Frontend:** React + Tailwind security dashboard using real API data.
6. **DevSecOps integration:** Dockerized app, CI security gate, integration tests, documentation.

## Security principles

- Never execute the image being scanned as part of vulnerability analysis.
- Pass subprocess arguments safely; do not build shell commands from untrusted input.
- Validate image references at the API boundary.
- Load YAML with safe parsing and validate policy keys/values.
- Treat scanner output as untrusted data.
- Do not commit secrets, virtual environments, caches, databases, or generated reports.
- A clean Trivy report does not prove an image is free of every security defect.

## License

See [LICENSE](LICENSE).
