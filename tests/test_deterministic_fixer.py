"""Unit tests for deterministic remediation fixes and rollback safety."""

from pathlib import Path

from supplyguard.remediation.deterministic_fixer import (
    fix_dependency,
    fix_sast_deterministic,
    fix_secret_hybrid,
)
from supplyguard.remediation.verifier import FixOutcome
from supplyguard.sast.scanner import SastFinding
from supplyguard.secrets.scanner import SecretFinding


def test_fix_dependency_bump(tmp_path: Path) -> None:
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests==2.25.1\nflask==2.0.1\n", encoding="utf-8")

    outcome, diff = fix_dependency(tmp_path, "requests", "2.31.0")
    assert outcome == FixOutcome.RESOLVED
    assert "requests==2.31.0" in req_file.read_text(encoding="utf-8")
    assert "-requests==2.25.1" in diff
    assert "+requests==2.31.0" in diff


def test_fix_sast_requests_verify_false(tmp_path: Path) -> None:
    test_py = tmp_path / "client.py"
    test_py.write_text('import requests\nresp = requests.get("https://example.com", verify=False)\n', encoding="utf-8")

    finding = SastFinding(
        file="client.py",
        line=2,
        rule_id="ai-requests-verify-false",
        severity="MEDIUM",
        cwe="CWE-295",
        message="verify=False",
    )

    outcome, diff = fix_sast_deterministic(tmp_path, finding)
    assert outcome == FixOutcome.RESOLVED
    assert "verify=False" not in test_py.read_text(encoding="utf-8")
    assert "-resp = requests.get" in diff


def test_fix_sast_flask_debug_true(tmp_path: Path) -> None:
    app_py = tmp_path / "app.py"
    app_py.write_text('from flask import Flask\napp = Flask(__name__)\napp.run(host="0.0.0.0", debug=True)\n', encoding="utf-8")

    finding = SastFinding(
        file="app.py",
        line=3,
        rule_id="ai-flask-debug-true",
        severity="MEDIUM",
        cwe="CWE-489",
        message="debug=True",
    )

    outcome, _diff = fix_sast_deterministic(tmp_path, finding)
    assert outcome == FixOutcome.RESOLVED
    assert "debug=False" in app_py.read_text(encoding="utf-8")


def test_fix_secret_hybrid(tmp_path: Path) -> None:
    finding = SecretFinding(
        file="config.py",
        line=5,
        rule_id="aws-access-key",
        match_preview="AKI...XYZ",
    )

    outcome, _diff, notice = fix_secret_hybrid(tmp_path, finding)
    assert outcome == FixOutcome.RESOLVED
    env_example = tmp_path / ".env.example"
    assert env_example.exists()
    assert "SECRET_AWS_ACCESS_KEY=" in env_example.read_text(encoding="utf-8")
    assert "Rotate the leaked credential" in notice
