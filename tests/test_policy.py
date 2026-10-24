import pytest

from aegistrail.models import Finding, ScanSummary
from aegistrail.policy import Policy, evaluate_policy


def sample_summary():
    return ScanSummary(
        image="demo:1",
        findings=[
            Finding("os", "pkg-a", "1.0", "1.1", "CRITICAL", "CVE-TEST-1"),
            Finding("os", "pkg-b", "2.0", "", "HIGH", "CVE-TEST-2"),
        ],
    )


def test_default_policy_fails_on_critical():
    passed, reasons = evaluate_policy(sample_summary(), Policy())
    assert passed is False
    assert "CVE-TEST-1" in reasons[0]


def test_default_policy_fails_on_high():
    summary = ScanSummary(
        "demo:1", [Finding("os", "pkg", "1", "", "HIGH", "CVE-HIGH")]
    )
    passed, reasons = evaluate_policy(summary, Policy())
    assert passed is False
    assert "CVE-HIGH" in reasons[0]


def test_unknown_is_reportable_but_not_blocking_by_default():
    summary = ScanSummary(
        "demo:1", [Finding("os", "pkg", "1", "2", "UNKNOWN", "CVE-UNKNOWN")]
    )
    assert evaluate_policy(summary, Policy())[0] is True
    assert "UNKNOWN" in Policy().report_severity


def test_policy_toml_loads(tmp_path):
    path = tmp_path / "policy.toml"
    path.write_text(
        'fail_on_severity = ["HIGH"]\n'
        'report_severity = ["UNKNOWN", "HIGH", "CRITICAL"]\n'
        'minimum_findings_to_fail = 2\n',
        encoding="utf-8",
    )
    policy = Policy.from_toml(path)
    assert policy.fail_on_severity == ("HIGH",)
    assert policy.minimum_findings_to_fail == 2


@pytest.mark.parametrize("minimum", [0, -1, "one"])
def test_invalid_minimum_is_rejected(tmp_path, minimum):
    path = tmp_path / "policy.toml"
    value = f'"{minimum}"' if isinstance(minimum, str) else str(minimum)
    path.write_text(
        f'fail_on_severity = ["CRITICAL"]\nminimum_findings_to_fail = {value}\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        Policy.from_toml(path)
