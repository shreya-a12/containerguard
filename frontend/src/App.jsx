
import { useCallback, useEffect, useState } from "react";
import {
  ShieldCheck,
  ShieldAlert,
  ScanLine,
  Boxes,
  Activity,
  Clock3,
  ArrowUpRight,
  RefreshCw,
  Search,
  ChevronRight,
  CircleCheck,
  AlertTriangle,
  Terminal,
  LockKeyhole,
  FileSearch,
  LoaderCircle,
  X,
} from "lucide-react";
import "./App.css";

const API = "http://127.0.0.1:8000";

const SEVERITIES = [
  { name: "Critical", color: "#fb7185" },
  { name: "High", color: "#fb923c" },
  { name: "Medium", color: "#facc15" },
  { name: "Low", color: "#60a5fa" },
  { name: "Unknown", color: "#94a3b8" },
];

function getSummary(scan) {
  return scan?.summary || scan?.result?.summary || scan || {};
}

function getSeverityCounts(scan) {
  const summary = getSummary(scan);
  const storedCounts =
    scan?.severity_counts ||
    summary?.severity_counts ||
    scan?.summary?.severity_counts ||
    {};

  return {
    Critical: Number(
      storedCounts.CRITICAL ?? storedCounts.Critical ??
      summary.critical ?? scan?.critical_count ?? 0
    ),
    High: Number(
      storedCounts.HIGH ?? storedCounts.High ??
      summary.high ?? scan?.high_count ?? 0
    ),
    Medium: Number(
      storedCounts.MEDIUM ?? storedCounts.Medium ??
      summary.medium ?? scan?.medium_count ?? 0
    ),
    Low: Number(
      storedCounts.LOW ?? storedCounts.Low ??
      summary.low ?? scan?.low_count ?? 0
    ),
    Unknown: Number(
      storedCounts.UNKNOWN ?? storedCounts.Unknown ??
      summary.unknown ?? scan?.unknown_count ?? 0
    ),
  };
}

function getTotal(scan) {
  const summary = getSummary(scan);
  const total =
    summary.total_vulnerabilities ??
    summary.total ??
    scan?.total_vulnerabilities;

  if (total !== undefined && total !== null) {
    return Number(total);
  }

  const counts = getSeverityCounts(scan);
  return Object.values(counts).reduce((sum, value) => sum + value, 0);
}

function getPolicyPassed(scan) {
  if (!scan) return undefined;

  const candidates = [
    scan.policy_passed,
    scan.policy?.passed,
    scan.policy_result?.passed,
    scan.passed,
  ];

  return candidates.find((value) => typeof value === "boolean");
}

function getFindings(scan) {
  const candidates = [
    scan?.findings,
    scan?.vulnerabilities,
    scan?.summary?.findings,
    scan?.summary?.vulnerabilities,
  ];

  return candidates.find(Array.isArray) || [];
}

function severityCountsFromFindings(findings = []) {
  const counts = {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
    Unknown: 0,
  };

  findings.forEach((finding) => {
    const severity = String(finding.severity || "Unknown").toLowerCase();
    const key = Object.keys(counts).find(
      (item) => item.toLowerCase() === severity
    );

    if (key) counts[key] += 1;
  });

  return counts;
}

function formatDate(value) {
  if (!value) return "Saved scan";

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);

  return date.toLocaleString();
}

function MetricCard({ icon: Icon, label, value, note, tone, delay = 0 }) {
  return (
    <article
      className="metric-card enter"
      style={{ animationDelay: `${delay}ms` }}
    >
      <div className={`metric-icon ${tone}`}>
        <Icon size={19} />
      </div>
      <p className="metric-label">{label}</p>
      <div className="metric-value">{value}</div>
      <p className="metric-note">{note}</p>
    </article>
  );
}

function App() {
  const [image, setImage] = useState("python:3.12-slim");
  const [scans, setScans] = useState([]);
  const [selected, setSelected] = useState(null);
  const [loading, setLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [apiOnline, setApiOnline] = useState(false);

  const loadScans = useCallback(async () => {
    setRefreshing(true);

    try {
      const response = await fetch(`${API}/scans?limit=20`);

      if (!response.ok) {
        throw new Error(`API returned HTTP ${response.status}`);
      }

      const data = await response.json();
      const items = Array.isArray(data)
        ? data
        : data.items || data.scans || [];

      setScans(items);
      setApiOnline(true);
      setError("");
    } catch (err) {
      setApiOnline(false);
      setError(
        err.message === "Failed to fetch"
          ? "Cannot reach the API. Check that FastAPI is running at 127.0.0.1:8000."
          : err.message || "Could not load scan history."
      );
    } finally {
      setRefreshing(false);
    }
  }, []);

  async function openScan(scan) {
    setError("");
    setNotice("");

    try {
      const response = await fetch(`${API}/scans/${scan.id}`);

      if (!response.ok) {
        throw new Error(
          response.status === 404
            ? "This scan could not be found."
            : `Could not load scan details (HTTP ${response.status}).`
        );
      }

      const detail = await response.json();
      setSelected(detail);
    } catch (err) {
      setError(err.message || "Could not load scan details.");
    }
  }

  async function runScan(event) {
    event.preventDefault();

    const imageReference = image.trim();
    if (!imageReference || loading) return;

    setLoading(true);
    setError("");
    setNotice("");
    setSelected(null);

    try {
      const response = await fetch(`${API}/scans`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ image: imageReference }),
      });

      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        const detail = typeof data.detail === "string"
          ? data.detail
          : `Scan failed (HTTP ${response.status}).`;

        throw new Error(detail);
      }

      setNotice(`Scan completed for ${imageReference}.`);
      await loadScans();

      const scanId = data.id ?? data.scan_id;

      if (scanId !== undefined && scanId !== null) {
        try {
          const detailResponse = await fetch(`${API}/scans/${scanId}`);

          if (detailResponse.ok) {
            setSelected(await detailResponse.json());
          } else {
            setSelected(data);
          }
        } catch {
          setSelected(data);
        }
      } else {
        setSelected(data);
      }
    } catch (err) {
      setError(err.message || "The scan could not be completed.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadScans();

    const interval = setInterval(() => {
      loadScans();
    }, 30000);

    return () => clearInterval(interval);
  }, [loadScans]);

  const latest = scans[0] || null;
  const latestSummary = getSummary(latest);
  const latestCounts = getSeverityCounts(latest);
  const selectedCounts = selected
    ? getSeverityCounts(selected)
    : latestCounts;

  const findings = getFindings(selected);
  const findingCounts = severityCountsFromFindings(findings);
  const displayedCounts = selected ? findingCounts : latestCounts;

  const total = getTotal(latest);
  const high = latestCounts.High;
  const policy = getPolicyPassed(latest);
  const selectedPolicy = getPolicyPassed(selected);

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="#overview">
          <span className="brand-mark">
            <ShieldCheck size={25} />
          </span>
          <span>
            <strong>
              container<span>guard</span>
            </strong>
            <small>CONTAINER SECURITY</small>
          </span>
        </a>

        <div className="side-caption">WORKSPACE</div>

        <a className="nav-link active" href="#overview">
          <Activity size={17} /> Overview
        </a>
        <a className="nav-link" href="#scanner">
          <ScanLine size={17} /> Image scanner
        </a>
        <a className="nav-link" href="#history">
          <Clock3 size={17} /> Scan history
        </a>
        <a className="nav-link" href="#findings">
          <FileSearch size={17} /> Findings
        </a>

        <div className="sidebar-bottom">
          <div className="side-caption">SYSTEM STATUS</div>
          <div className="system-card">
            <span className={`status-dot ${apiOnline ? "online" : ""}`} />
            <div>
              <strong>Security API</strong>
              <small>
                {apiOnline ? "Connected" : "Waiting for connection"}
              </small>
            </div>
          </div>
          <div className="sidebar-footer">
            <LockKeyhole size={13} /> Local security workspace
          </div>
        </div>
      </aside>

      <main className="main-content" id="overview">
        <header className="topbar">
          <div className="breadcrumb">
            Workspace <ChevronRight size={14} /> <strong>Overview</strong>
          </div>

          <div className="topbar-right">
            <span className={`connection-pill ${apiOnline ? "connected" : ""}`}>
              <span className={`status-dot ${apiOnline ? "online" : ""}`} />
              {apiOnline ? "API connected" : "API offline"}
            </span>

            <button
              className="icon-button"
              onClick={loadScans}
              title="Refresh scans"
              aria-label="Refresh scans"
              disabled={refreshing}
            >
              <RefreshCw
                size={16}
                className={refreshing ? "spin" : ""}
              />
            </button>
          </div>
        </header>

        <section className="page-heading enter">
          <div>
            <div className="eyebrow">
              <span className="eyebrow-line" />
              DEVSECOPS / SECURITY CENTER
            </div>
            <h1>
              Container security <span>overview.</span>
            </h1>
            <p>
              Scan container images, uncover vulnerabilities, and enforce
              security policies.
            </p>
          </div>

          <div className="heading-chip">
            <ShieldCheck size={16} /> Continuous protection
          </div>
        </section>

        {error && (
          <div className="alert error-alert" role="alert">
            <AlertTriangle size={18} />
            <span>{error}</span>
            <button onClick={() => setError("")} aria-label="Dismiss error">
              <X size={16} />
            </button>
          </div>
        )}

        {notice && (
          <div className="alert success-alert" role="status">
            <CircleCheck size={18} />
            <span>{notice}</span>
            <button onClick={() => setNotice("")} aria-label="Dismiss notice">
              <X size={16} />
            </button>
          </div>
        )}

        <section className="metrics-grid">
          <MetricCard
            icon={Boxes}
            label="Images scanned"
            value={scans.length}
            note="Recent scan records"
            tone="cyan"
            delay={50}
          />
          <MetricCard
            icon={ShieldAlert}
            label="Latest vulnerabilities"
            value={total}
            note="From latest scan"
            tone="orange"
            delay={100}
          />
          <MetricCard
            icon={AlertTriangle}
            label="High severity"
            value={high}
            note="Requires attention"
            tone="amber"
            delay={150}
          />
          <MetricCard
            icon={ShieldCheck}
            label="Policy status"
            value={
              !latest
                ? "—"
                : policy === true
                  ? "PASS"
                  : policy === false
                    ? "FAIL"
                    : "—"
            }
            note={
              policy === false
                ? "Policy violations detected"
                : policy === true
                  ? "No blocking violations"
                  : "Waiting for scan"
            }
            tone={policy === false ? "red" : "green"}
            delay={200}
          />
        </section>

        <section className="content-grid">
          <article className="panel scanner-panel" id="scanner">
            <div className="panel-heading">
              <div>
                <span className="panel-kicker">VULNERABILITY ANALYSIS</span>
                <h2>Scan an image</h2>
              </div>
              <span className="panel-icon">
                <ScanLine size={19} />
              </span>
            </div>

            <p className="panel-description">
              Enter a public container image reference to inspect its packages
              and known vulnerabilities.
            </p>

            <form onSubmit={runScan} className="scan-form">
              <label htmlFor="image-ref">CONTAINER IMAGE</label>
              <div className="input-wrap">
                <Terminal size={17} />
                <input
                  id="image-ref"
                  value={image}
                  onChange={(event) => setImage(event.target.value)}
                  placeholder="e.g. nginx:latest"
                  maxLength={255}
                  required
                />
              </div>

              <div className="form-hint">
                <span className="status-dot online" />
                Example: python:3.12-slim
              </div>

              <button className="primary-button" disabled={loading}>
                {loading ? (
                  <>
                    <LoaderCircle size={17} className="spin" />
                    Scanning image…
                  </>
                ) : (
                  <>
                    <ScanLine size={17} />
                    Start security scan
                    <ArrowUpRight size={17} />
                  </>
                )}
              </button>
            </form>

            <div className="scanner-foot">
              <LockKeyhole size={14} />
              Powered by Trivy vulnerability scanning
            </div>
          </article>

          <article className="panel severity-panel">
            <div className="panel-heading">
              <div>
                <span className="panel-kicker">RISK DISTRIBUTION</span>
                <h2>Severity breakdown</h2>
              </div>
              <span className="panel-icon">
                <Activity size={19} />
              </span>
            </div>

            <p className="panel-description">
              {selected
                ? `Findings from scan #${selected.id ?? "selected"}.`
                : "Findings from the latest scan."}
            </p>

            <div className="severity-list">
              {SEVERITIES.map(({ name, color }) => {
                const value = displayedCounts[name] ?? 0;
                const max = Math.max(
                  1,
                  ...SEVERITIES.map(({ name: severityName }) =>
                    Number(displayedCounts[severityName] ?? 0)
                  )
                );

                return (
                  <div className="severity-row" key={name}>
                    <div className="severity-meta">
                      <span>
                        <i style={{ background: color }} />
                        {name}
                      </span>
                      <strong>{value}</strong>
                    </div>
                    <div className="bar-track">
                      <div
                        className="bar-fill"
                        style={{
                          width: `${Math.min(100, (value / max) * 100)}%`,
                          background: color,
                        }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>

            <div className="severity-foot">
              <span className="status-dot online" />
              {selected ? "Selected scan details" : "Latest scan summary"}
            </div>
          </article>
        </section>

        <section className="panel history-panel" id="history">
          <div className="panel-heading history-heading">
            <div>
              <span className="panel-kicker">AUDIT TRAIL</span>
              <h2>Recent scans</h2>
            </div>
            <div className="history-actions">
              <span className="record-count">{scans.length} records</span>
              <button
                className="text-button"
                onClick={loadScans}
                disabled={refreshing}
              >
                Refresh <RefreshCw size={14} />
              </button>
            </div>
          </div>

          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>IMAGE</th>
                  <th>SCAN ID</th>
                  <th>VULNERABILITIES</th>
                  <th>POLICY</th>
                  <th>DETAILS</th>
                </tr>
              </thead>

              <tbody>
                {scans.map((scan) => {
                  const passed = getPolicyPassed(scan);

                  return (
                    <tr
                      key={scan.id}
                      className={selected?.id === scan.id ? "selected-row" : ""}
                    >
                      <td>
                        <div className="image-cell">
                          <span className="table-icon">
                            <Boxes size={16} />
                          </span>
                          <span>
                            {scan.image || scan.image_ref || "Unknown image"}
                            <small>
                              {formatDate(scan.created_at || scan.scanned_at)}
                            </small>
                          </span>
                        </div>
                      </td>

                      <td className="mono">#{scan.id}</td>

                      <td>
                        <span className="vuln-count">{getTotal(scan)}</span>
                      </td>

                      <td>
                        <span
                          className={`policy-badge ${
                            passed === true
                              ? "pass"
                              : passed === false
                                ? "fail"
                                : "pending"
                          }`}
                        >
                          {passed === true
                            ? "PASS"
                            : passed === false
                              ? "FAIL"
                              : "UNKNOWN"}
                        </span>
                      </td>

                      <td>
                        <button
                          className="row-action"
                          onClick={() => openScan(scan)}
                          aria-label={`View scan ${scan.id}`}
                        >
                          <Search size={15} /> View <ChevronRight size={14} />
                        </button>
                      </td>
                    </tr>
                  );
                })}

                {!scans.length && (
                  <tr>
                    <td colSpan="5" className="empty-state">
                      <FileSearch size={24} />
                      <strong>No scans yet</strong>
                      <span>Run your first scan above to populate this table.</span>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>

        <section className="panel findings-panel" id="findings">
          <div className="panel-heading">
            <div>
              <span className="panel-kicker">SCAN INSPECTION</span>
              <h2>
                {selected
                  ? `Findings · Scan #${selected.id ?? "—"}`
                  : "Vulnerability findings"}
              </h2>
            </div>

            {selected && (
              <button
                className="text-button"
                onClick={() => setSelected(null)}
              >
                Clear selection <X size={14} />
              </button>
            )}
          </div>

          {selected ? (
            <>
              <div className="detail-summary">
                <div>
                  <span>Image</span>
                  <strong>
                    {selected.image || selected.image_ref || "Container image"}
                  </strong>
                </div>
                <div>
                  <span>Policy result</span>
                  <strong
                    className={
                      selectedPolicy === false
                        ? "text-danger"
                        : selectedPolicy === true
                          ? "text-success"
                          : ""
                    }
                  >
                    {selectedPolicy === true
                      ? "PASS"
                      : selectedPolicy === false
                        ? "FAIL"
                        : "Unknown"}
                  </strong>
                </div>
                <div>
                  <span>Total findings</span>
                  <strong>{getTotal(selected)}</strong>
                </div>
              </div>

              <div className="table-wrap findings-table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>SEVERITY</th>
                      <th>VULNERABILITY</th>
                      <th>PACKAGE</th>
                      <th>INSTALLED VERSION</th>
                    </tr>
                  </thead>

                  <tbody>
                    {findings.slice(0, 100).map((finding, index) => {
                      const severity = String(finding.severity || "Unknown");
                      const color =
                        SEVERITIES.find(
                          (item) =>
                            item.name.toLowerCase() === severity.toLowerCase()
                        )?.color || "#94a3b8";

                      return (
                        <tr
                          key={`${
                            finding.vulnerability_id || finding.id || "finding"
                          }-${index}`}
                        >
                          <td>
                            <span
                              className="severity-tag"
                              style={{
                                color,
                                borderColor: `${color}55`,
                                background: `${color}12`,
                              }}
                            >
                              {severity}
                            </span>
                          </td>
                          <td className="mono">
                            {finding.vulnerability_id || finding.id || "—"}
                          </td>
                          <td>
                            {finding.package_name ||
                              finding.pkg_name ||
                              finding.package ||
                              "—"}
                          </td>
                          <td className="mono">
                            {finding.installed_version ||
                              finding.version ||
                              "—"}
                          </td>
                        </tr>
                      );
                    })}

                    {!findings.length && (
                      <tr>
                        <td colSpan="4" className="empty-state">
                          No detailed findings were returned for this scan.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>

              {findings.length > 100 && (
                <p className="table-note">
                  Showing 100 of {findings.length} findings.
                </p>
              )}
            </>
          ) : (
            <div className="findings-empty">
              <div className="empty-graphic">
                <FileSearch size={25} />
              </div>
              <strong>Select a scan to inspect findings</strong>
              <span>
                Choose View in the scan history table to see its vulnerability
                details.
              </span>
            </div>
          )}
        </section>

        <footer className="page-footer">
          <span>
            <ShieldCheck size={15} /> ContainerGuard
            <span className="footer-muted">· Container security workspace</span>
          </span>
          <span>
            Built for secure-by-default delivery{" "}
            <span className="footer-accent">●</span>
          </span>
        </footer>
      </main>
    </div>
  );
}

export default App;
