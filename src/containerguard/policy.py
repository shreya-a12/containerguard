"""Load and evaluate configurable vulnerability policies."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from containerguard.analysis import SEVERITIES
from containerguard.errors import ConfigurationError

DEFAULT_POLICY: dict[str, Any] = {
    "fail_on_severity": ["CRITICAL", "HIGH"],
    "fail_on_unfixed": False,
}


def load_policy(path: str | Path | None = None) -> dict[str, Any]:
    """Load a policy YAML file, or return the documented default policy."""
    if path is None:
        return dict(DEFAULT_POLICY)

    policy_path = Path(path)
    try:
        raw = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigurationError(f"Cannot read policy '{policy_path}': {exc}") from exc
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"Policy '{policy_path}' is not valid YAML: {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigurationError("Policy must be a YAML mapping.")
    unknown = set(raw) - {"fail_on_severity", "fail_on_unfixed"}
    if unknown:
        raise ConfigurationError(f"Unknown policy key(s): {', '.join(sorted(unknown))}")

    severities = raw.get("fail_on_severity", DEFAULT_POLICY["fail_on_severity"])
    if not isinstance(severities, list) or any(not isinstance(item, str) for item in severities):
        raise ConfigurationError("'fail_on_severity' must be a list of severity names.")
    normalized = [item.upper() for item in severities]
    invalid = sorted(set(normalized) - set(SEVERITIES))
    if invalid:
        raise ConfigurationError(f"Invalid severity name(s): {', '.join(invalid)}")

    fail_on_unfixed = raw.get("fail_on_unfixed", False)
    if not isinstance(fail_on_unfixed, bool):
        raise ConfigurationError("'fail_on_unfixed' must be true or false.")

    return {"fail_on_severity": list(dict.fromkeys(normalized)), "fail_on_unfixed": fail_on_unfixed}


def evaluate_policy(summary: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    """Evaluate findings against policy and return a stable pass/fail result."""
    blocked_severities = set(policy["fail_on_severity"])
    violations = []
    for finding in summary.get("findings", []):
        severity_blocked = finding.get("severity") in blocked_severities
        unfixed_blocked = policy["fail_on_unfixed"] and not finding.get("fixed_version")
        if severity_blocked or unfixed_blocked:
            reasons = []
            if severity_blocked:
                reasons.append(f"severity {finding.get('severity')}")
            if unfixed_blocked:
                reasons.append("no known fixed version")
            violations.append({
                "vulnerability_id": finding.get("vulnerability_id", "UNKNOWN-ID"),
                "package": finding.get("package", "unknown"),
                "severity": finding.get("severity", "UNKNOWN"),
                "reasons": reasons,
            })
    return {
        "passed": not violations,
        "blocked_severities": sorted(blocked_severities),
        "fail_on_unfixed": policy["fail_on_unfixed"],
        "violation_count": len(violations),
        "violations": violations,
    }
