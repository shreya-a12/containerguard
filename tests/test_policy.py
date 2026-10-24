import pytest

from containerguard.errors import ConfigurationError
from containerguard.policy import evaluate_policy, load_policy


def test_default_policy_blocks_critical_and_high():
    policy = load_policy()
    assert policy["fail_on_severity"] == ["CRITICAL", "HIGH"]
    assert policy["fail_on_unfixed"] is False


def test_custom_policy_and_evaluation(tmp_path):
    path = tmp_path / "policy.yml"
    path.write_text("fail_on_severity:\n  - high\nfail_on_unfixed: true\n", encoding="utf-8")
    policy = load_policy(path)
    summary = {"findings": [
        {"vulnerability_id": "CVE-1", "package": "openssl", "severity": "HIGH", "fixed_version": "3.1"},
        {"vulnerability_id": "CVE-2", "package": "zlib", "severity": "LOW", "fixed_version": ""},
    ]}
    result = evaluate_policy(summary, policy)
    assert result["passed"] is False
    assert result["violation_count"] == 2


def test_policy_rejects_unknown_severity(tmp_path):
    path = tmp_path / "bad.yml"
    path.write_text("fail_on_severity: [SEVERE]\n", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="Invalid severity"):
        load_policy(path)


def test_policy_rejects_unknown_key(tmp_path):
    path = tmp_path / "bad.yml"
    path.write_text("block_all: true\n", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="Unknown policy key"):
        load_policy(path)
